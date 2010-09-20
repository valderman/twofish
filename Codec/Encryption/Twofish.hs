{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeSynonymInstances #-}

-- Module      : Codec.Encryption.Twofish
-- Copyright   : (c) Ron Leisti 2010
-- License     : BSD3
-- Maintainer  : ron.leisti@gmail.com

-- |Implements the Twofish symmetric block cipher, designed by:
-- Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall,
-- and Niels Ferguson.
-- 
-- Implemented from the paper entitled "Twofish: A 128-Bit Block Cipher",
-- <http://www.counterpane.com/twofish.html>
-- with help from the reference C implementation.
--
-- This module provides two methods for constructiong a Twofish cipher
-- from a 128, 192 or 256 bit key.  The mkCipher function allows you 
-- to customize the number of rounds, while the mkStdCipher function
-- gives you the standard 16 rounds.
module Codec.Encryption.Twofish
   (
   -- * Classes
   Key
   -- * Types
   ,TwofishCipher
   -- * Functions
   ,mkStdCipher
   ,mkCipher
   -- * Curiosities
   ,q0o
   ,q1o
   ) where

import Crypto.Classes
import Data.Array.Unboxed hiding (index)
import Data.Binary
import qualified Data.Binary.Get as BinaryGet
import qualified Data.Binary.Put as BinaryPut
import Data.Bitlib as Bitlib
import Data.Bits
import qualified Data.ByteString as ByteString
import Data.Cipher
import Data.LargeWord
import Data.Serialize
import qualified Data.Serialize.Get as SerializeGet
import Data.Serialize.Put as SerializePut
import Data.Tagged
import Prelude hiding (length, drop, reverse, take)
import qualified Prelude as P

-- |A key is a vector of bytes of a certain size (given in bits).
-- Twofish suppports key sizes of 128, 192, and 256 bits.
class (Bits a, Integral a) => Key a where
    -- |Extracts the nth byte from a key (starting with 0, the least
    -- significant byte).
    --
    -- This particular implementation works around a bug in the
    -- Data.LargeWord module involving right shifts.
    keyByte :: a -> Int -> Word8
    keyByte w n = let w' = fromIntegral w :: Integer
                  in fromIntegral $ (w' `shiftR` (8 * n)) .&. 0xff

-- Standard key sizes
instance Key Word128
instance Key Word192
instance Key Word256

-- |A keyed Twofish cipher capable of both encryption and decryption.
data TwofishCipher = C { eb :: Block -> Block,
                         db :: Block -> Block }

-- |Twofish is a 128 bit block cipher.
instance Cipher Word128 TwofishCipher where
    encrypt c = liftCryptor (eb c)
    decrypt c = liftCryptor (db c)

-- |Lift a crytographic transformation of a block into a
-- transformation of a byte vector.
liftCryptor :: (Block -> Block) -> Word128 -> Word128
liftCryptor c = deBlock . c . mkBlock

data TwofishKey = TwofishKey {  twofishKeyCipher  :: TwofishCipher
                               ,twofishKeyContent :: Word256
                             }

instance (Binary TwofishKey) where
    put = BinaryPut.putByteString . ByteString.pack . Bitlib.unpack . twofishKeyContent
    get = do bytes <- BinaryGet.getBytes 32
             let key = Bitlib.pack . ByteString.unpack $ bytes
             let twofishKey = TwofishKey {  twofishKeyCipher  = mkStdCipher key
                                           ,twofishKeyContent = key
                                         } 
             return twofishKey 

instance (Serialize TwofishKey) where
    put = SerializePut.putByteString . ByteString.pack . Bitlib.unpack . twofishKeyContent
    get = do bytes <- SerializeGet.getBytes 32
             let key = Bitlib.pack . ByteString.unpack $ bytes
             let twofishKey = TwofishKey {  twofishKeyCipher  = mkStdCipher key
                                           ,twofishKeyContent = key
                                         } 
             return twofishKey 

instance (BlockCipher TwofishKey) where
    blockSize        = Tagged 128
    encryptBlock k s = let bytes       = ByteString.unpack s
                           ws          = Bitlib.packMany (0 :: Word128) bytes
                           blocks      = map mkBlock ws
                           cryptBlocks = map (eb (twofishKeyCipher k)) blocks
                           cryptWords  = map deBlock cryptBlocks
                           cryptBytes  = unpackMany cryptWords
                       in ByteString.pack cryptBytes
    decryptBlock k s = let cryptBytes  = ByteString.unpack s
                           cryptWords  = Bitlib.packMany (0 :: Word128) cryptBytes
                           cryptBlocks = map mkBlock cryptWords
                           blocks      = map (db (twofishKeyCipher k)) cryptBlocks
                           ws          = map deBlock blocks
                           bytes       = unpackMany ws
                       in ByteString.pack bytes
    keyLength _ = 256
    buildKey s  = let word = Bitlib.pack (ByteString.unpack s) :: Word256
                  in Just TwofishKey {  twofishKeyCipher  = mkStdCipher word
                                       ,twofishKeyContent = word
                                     }
                           
-- |A 128 bit data block, decomposed into four words
type Block = (Word32, Word32, Word32, Word32)

-- |Decompose a 128 bit word into 4 32 bit words
-- 
-- This particular implementation works around a bug
-- in the Data.LargeWord module involving right shifts.
mkBlock :: Word128 -> Block
mkBlock b = 
    let b' = fromIntegral b :: Integer
        w0 = b' .&. 0xffffffff
        w1 = (b' `shiftR` 32) .&. 0xffffffff
        w2 = (b' `shiftR` 64) .&. 0xffffffff
        w3 = (b' `shiftR` 96) .&. 0xffffffff
    in (fromIntegral w0, fromIntegral w1,
        fromIntegral w2, fromIntegral w3)

-- |Compose 4 32 bit words into a 128 bit word
deBlock :: Block -> Word128
deBlock (w0, w1, w2, w3) =
    let w0' = fromIntegral w0
        w1' = fromIntegral w1
        w2' = fromIntegral w2
        w3' = fromIntegral w3
    in w0' .|. (w1' `shiftL` 32) .|. (w2' `shiftL` 64) .|.
       (w3' `shiftL` 96)

-- |Constructs a standard Twofish cipher from the given key
mkStdCipher :: (Key a) => a -> TwofishCipher
mkStdCipher = mkCipher 16

-- |Constructs an encryption/decryption cipher from the given key, and
-- a given number of rounds (standard Twofish uses 16 rounds)
mkCipher :: (Key a) => Int -> a -> TwofishCipher
mkCipher numRounds key =
    let s    = mkS key
        h    = mkfH key
        k    = mkK key numRounds h
        g    = mkG h s
    in C { eb = \(p0, p1, p2, p3) -> 
                     let w = (p0 `xor` k 0, p1 `xor` k 1,
                              p2 `xor` k 2, p3 `xor` k 3)
                         (r0, r1, r2, r3) = encryptRounds g k numRounds w
                         c0 = r2 `xor` k 4
                         c1 = r3 `xor` k 5
                         c2 = r0 `xor` k 6
                         c3 = r1 `xor` k 7
                     in (c0, c1, c2, c3)
           ,db = \(c0, c1, c2, c3) ->
                     let w = (c0 `xor` k 4, c1 `xor` k 5,
                              c2 `xor` k 6, c3 `xor` k 7)
                         (r0, r1, r2, r3) = decryptRounds g k numRounds w
                         p0 = r2 `xor` k 0
                         p1 = r3 `xor` k 1
                         p2 = r0 `xor` k 2
                         p3 = r1 `xor` k 3
                      in (p0, p1, p2, p3) }

-- |This function performs n rounds of the encryption algorithm
encryptRounds :: GFunc -> KIndexor -> Int -> Block -> Block
encryptRounds g k n b = foldl roundT b [0..(n-1)]
    where roundT :: Block -> Int -> Block
          roundT (r0, r1, r2, r3) r =
              let t0  = g r0
                  t1  = g (r1 `rotateL` 8)
                  f0  = t0 + t1 + k (2 * r + 8)
                  f1  = t0 + 2 * t1 + k (2 * r + 9)
                  r0' = (r2 `xor` f0) `rotateR` 1
                  r1' = (r3 `rotateL` 1) `xor` f1
                  r2' = r0
                  r3' = r1
              in (r0', r1', r2', r3')

-- |This function performs n rounds of the decryption algorithm
decryptRounds :: GFunc -> KIndexor -> Int -> Block -> Block
decryptRounds g k n b = foldr roundT b [0..(n-1)]
    where roundT :: Int -> Block -> Block
          roundT r (r0, r1, r2, r3) =
              let t0  = g r0
                  t1  = g (r1 `rotateL` 8)
                  f0  = t0 + t1 + k (2 * r + 8)
                  f1  = t0 + 2 * t1 + k (2 * r + 9)
                  r0' = (r2 `rotateL` 1) `xor` f0
                  r1' = (r3 `xor` f1) `rotateR` 1
                  r2' = r0
                  r3' = r1
             in (r0', r1', r2', r3')

-- Word vector
type WordVector = UArray Int Word32

-- Several function and vector types used within Twofish;
-- made explicit for clarity.
type HFunc = Word32 -> WordVector -> Word32
type GFunc = Word32 -> Word32
type SVector = WordVector
type KIndexor = Int -> Word32

-- Calculates the k value of a key (a function of the key length)
fK :: (Key a) => a -> Int
fK key = bitSize key `div` 64

-- Generates a G function from an H function and an S vector
-- The G function forms the 'heart' of Twofish
mkG :: HFunc -> SVector -> GFunc
mkG h s x = h x s

-- Generates an S vector from a key
-- This vector is combined with the H function to produce the
-- G function.
mkS :: (Key a) => a -> SVector
mkS key = reverse . mkVector $ [s i | i <- [0..(k - 1)]]
    where s :: Int -> Word32
          s i = rs (selectWord (\j -> 8 * i + j) key)
                   (selectWord (\j -> 8 * i + j + 4) key)
          k   = fK key

reverse :: WordVector -> WordVector
reverse = mkVector . P.reverse . elems

mkVector :: [Word32] -> WordVector
mkVector w = listArray (0, P.length w - 1) w

-- Generates the expanded key indexor from a key, the number
-- of rounds, and an H function.
-- The number of rounds determines the length of the expanded key
mkK :: (Key a) => a -> Int -> HFunc -> KIndexor
mkK key n fH =
    let me = mkVector [m i | i <- [0..(2 * k - 2)], even i]
        mo = mkVector [m i | i <- [1..(2 * k - 1)], odd i]
        ks = mkVector [getK me mo i | i <- [0..(8 + (n * 2) - 1)]]
    in (ks !)
    where getK :: WordVector -> WordVector -> Int -> Word32
          getK me mo i
              | even i    = ai me (ie i) + bi mo (ie i)
              | otherwise = (ai me (io i) + 2 * bi mo (io i)) `rotateL` 9
          ie i = i `div` 2
          io i = (i - 1) `div` 2

          ai :: WordVector -> Int -> Word32
          ai me i = fH (2 * fromIntegral i * rho) me

          bi :: WordVector -> Int -> Word32
          bi mo i = fH ((2 * fromIntegral i + 1) * rho) mo `rotateL` 8

          m i = selectWord (\j -> 4 * i + j) key
          k   = fK key

-- Generate an H function from the given key
mkfH :: (Key a) => a -> HFunc
mkfH key = let k   = fK key
               q0  = (q0c !)
               q1  = (q1c !)
               mxX = mkMdsX
               mxY = mkMdsY
           in fHGenerator q0 q1 mxX mxY k

-- Most of the work in the Twofish cipher happens here.
fHGenerator :: (Word8 -> Word8) -> (Word8 -> Word8) -> ByteVector -> ByteVector -> Int -> Word32 -> WordVector -> Word32
fHGenerator q0 q1 mxX mxY k x l = mds mxX mxY (y0, y1, y2, y3)
    where y0 = q1 $ q0 (q0 (yij 2 0) `xor` lij 1 0) `xor` lij 0 0
          y1 = q0 $ q0 (q1 (yij 2 1) `xor` lij 1 1) `xor` lij 0 1
          y2 = q1 $ q1 (q0 (yij 2 2) `xor` lij 1 2) `xor` lij 0 2
          y3 = q0 $ q1 (q1 (yij 2 3) `xor` lij 1 3) `xor` lij 0 3

          yij :: Int -> Int -> Word8
          yij 3 j
              | k == 4    = let qx = if j `elem` [0, 3] then q1 else q0
                            in qx (yij 4 j) `xor` lij 3 j
              | otherwise = xj j
          yij 2 j 
              | k >= 3    = let qx = if j `elem` [0, 1] then q1 else q0
                            in qx (yij 3 j) `xor` lij 2 j
              | otherwise = xj j
          yij _ j = xj j

          xj :: Int -> Word8
          xj = byteN x

          lij :: Int -> Int -> Word8
          lij i = byteN (l ! i)

-- Multiply a vector of bytes by the MDS matrix
mds :: ByteVector -> ByteVector -> (Word8, Word8, Word8, Word8) -> Word32
mds mxX mxY (x0, x1, x2, x3) =
    let r0 = x0 `xor` (mxY ! x1) `xor` (mxX ! x2) `xor` (mxX ! x3)
        r1 = (mxX ! x0) `xor` (mxY ! x1) `xor` (mxY ! x2) `xor` x3
        r2 = (mxY ! x0) `xor` (mxX ! x1) `xor` x2 `xor` (mxY ! x3)
        r3 = (mxY ! x0) `xor` x1 `xor` (mxY ! x2) `xor` (mxX ! x3)
    in fromIntegral r0 .|. (fromIntegral r1 `shiftL` 8) .|.
       (fromIntegral r2 `shiftL` 16) .|.  (fromIntegral r3 `shiftL` 24)

-- A byte mapping used as part of the MDS matrix multiply
mkMdsX :: ByteVector
mkMdsX = mkByteVector $ map f [0..255]
    where f x = x `xor` case (x .&. 0x03) of
                            1 -> (x `shiftR` 2) `xor` 0x5a
                            2 -> (x `shiftR` 2) `xor` 0xb4
                            3 -> (x `shiftR` 2) `xor` 0xee
                            _ -> (x `shiftR` 2)

-- A byte mapping used as part of the MDS matrix multiply
mkMdsY :: ByteVector
mkMdsY = mkByteVector $ map f [0..255]
    where f x = x `xor` (x `shiftR` 2) `xor` case (x .&. 0x03) of
                                                 1 -> (x `shiftR` 1) `xor` 0xee
                                                 2 -> (x `shiftR` 1) `xor` 0xb4
                                                 3 -> (x `shiftR` 1) `xor` 0x5a
                                                 _ -> (x `shiftR` 1)

-- Multiply a vector of bytes by the RS matrix
rs :: Word32 -> Word32 -> Word32
rs k0 k1 =
   rsRem4 (rsRem4 k1 `xor` k0)
   where rsRem4  = rsRem . rsRem . rsRem .rsRem

rsRem :: Word32 -> Word32
rsRem x = let b  = x `shiftR` 24
              g2 = case b .&. 0x80 of
                       0 -> (b `shiftL` 1) .&. 0xff
                       _ -> ((b `shiftL` 1) `xor` 0x14d) .&. 0xff
              g3 = case b .&. 1 of
                       0 -> ((b `shiftR` 1) .&. 0x7f) `xor` g2
                       _ -> ((b `shiftR` 1) .&. 0x7f) `xor` (0x14d `shiftR` 1) `xor` g2
          in (x `shiftL` 8) `xor` (g3 `shiftL` 24) `xor` (g2 `shiftL` 16) `xor`
             (g3 `shiftL` 8) `xor` b

-- The rho constant has the property that i * rho is
-- a word consisting of four equal bytes, each equal to i.
-- (where 0 <= i <= 255)
rho :: Word32
rho = 0x1010101

-- Extract 4 specific bytes from a byte vector in order to
-- assemble a 32 bit word.  A selector function is used to
-- translate the indicies [0, 1, 2, 3] into the actual
-- indicies of bytes within the vector for selection.
selectWord :: (Key a) => (Int -> Int) -> a -> Word32
selectWord f b = let b0 = select $ f 0
                     b1 = select $ f 1
                     b2 = select $ f 2
                     b3 = select $ f 3
                 in b0 .|. (b1 `shiftL` 8) .|. (b2 `shiftL` 16) .|.
                    (b3 `shiftL` 24)
    where select i = fromIntegral $ keyByte b i

-- Extracts the n'th byte from a word
byteN :: (Integral a, Bits a) => a -> Int -> Word8
byteN w n = let s = fromIntegral (n `shiftL` 3)
            in fromIntegral $ (w .&. (0xff `shiftL` s)) `shiftR` s

type ByteVector = UArray Word8 Word8

mkByteVector :: [Word8] -> ByteVector
mkByteVector = listArray (0, 255)

q0c :: ByteVector
q0c = mkByteVector [169,103,179,232,4,253,163,118,154,146,128,120,228,221,209,56,13,198,53,152,24,247,236,108,67,117,55,38,250,19,148,72,242,208,139,48,132,84,223,35,25,91,61,89,243,174,162,130,99,1,131,46,217,81,155,124,166,235,165,190,22,12,227,97,192,140,58,245,115,44,37,11,187,78,137,107,83,106,180,241,225,230,189,69,226,244,182,102,204,149,3,86,212,28,30,215,251,195,142,181,233,207,191,186,234,119,57,175,51,201,98,113,129,121,9,173,36,205,249,216,229,197,185,77,68,8,134,231,161,29,170,237,6,112,178,210,65,123,160,17,49,194,39,144,32,246,96,255,150,92,177,171,158,156,82,27,95,147,10,239,145,133,73,238,45,79,143,59,71,135,109,70,214,62,105,100,42,206,203,47,252,151,5,122,172,127,213,26,75,14,167,90,40,20,63,41,136,60,76,2,184,218,176,23,85,31,138,125,87,199,141,116,183,196,159,114,126,21,34,18,88,7,153,52,110,80,222,104,101,188,219,248,200,168,43,64,220,254,50,164,202,16,33,240,211,93,15,0,111,157,54,66,74,94,193,224]

q1c :: ByteVector
q1c = mkByteVector [117,243,198,244,219,123,251,200,74,211,230,107,69,125,232,75,214,50,216,253,55,113,241,225,48,15,248,27,135,250,6,63,94,186,174,91,138,0,188,157,109,193,177,14,128,93,210,213,160,132,7,20,181,144,44,163,178,115,76,84,146,116,54,81,56,176,189,90,252,96,98,150,108,66,247,16,124,40,39,140,19,149,156,199,36,70,59,112,202,227,133,203,17,208,147,184,166,131,32,255,159,119,195,204,3,111,8,191,64,231,43,226,121,12,170,130,65,58,234,185,228,154,164,151,126,218,122,23,102,148,161,29,61,240,222,179,11,114,167,28,239,209,83,62,143,51,38,95,236,118,42,73,129,136,238,33,196,26,235,217,197,57,153,205,173,49,139,1,24,35,221,31,78,45,249,72,79,242,101,142,120,92,88,25,141,229,152,87,103,127,5,100,175,99,182,254,245,183,60,165,206,233,104,68,224,77,67,105,41,46,172,21,89,168,10,158,110,71,223,52,53,106,207,220,34,201,192,155,137,212,237,171,18,162,13,82,187,2,47,169,215,97,30,180,80,4,246,194,22,37,134,86,85,9,190,145]
 
-- The following code is for pedagogical purposes only; the Q0 and Q1
-- values are precomputed into q0c and q1c

-- |Generates the 'q0' byte vector using the algorithm specified in
-- the Twofish paper.  This function isn't used by the cipher; instead
-- the pre-computed array is contained in the code.
q0o :: Word8 -> Word8
q0o = let t0 = mkByteVector [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2,
                             0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4]
          t1 = mkByteVector [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5,
                             0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD]
          t2 = mkByteVector [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0,
                             0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1]
          t3 = mkByteVector [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE,
                             0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA]
      in q t0 t1 t2 t3

-- |Generates the 'q1' byte vector using the algorithm specified in
-- the Twofish paper.  This function isn't used by the cipher; instead
-- the pre-computed array is contained in the code.
q1o :: Word8 -> Word8
q1o = let t0 = mkByteVector [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE,
                             0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5]
          t1 = mkByteVector [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7,
                             0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8]
          t2 = mkByteVector [0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA,
                             0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF]
          t3 = mkByteVector [0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE,
                             0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA]
      in q t0 t1 t2 t3

-- Generates a 'q' transformation from 4 input vectors.
-- Each vector consists of 26 bytes.
q :: ByteVector -> ByteVector -> ByteVector -> ByteVector -> Word8 -> Word8
q t0 t1 t2 t3 x = 16 * b4 + a4
    where a0 = x `div` 16
          b0 = x `mod` 16
          a1 = a0 `xor` b0
          b1 = a0 `xor` ror4 b0 1 `xor` (8 * a0) `mod` 16
          a2 = t0 ! a1
          b2 = t1 ! b1
          a3 = a2 `xor` b2
          b3 = a2 `xor` ror4 b2 1 `xor` (8 * a2) `mod` 16
          a4 = t2 ! a3
          b4 = t3 ! b3

-- Rotates a nibble (least significant 4 bits of the given byte)
ror4 :: Word8 -> Int -> Word8
ror4 x n = ((x .&. 0xf) `shiftR` n) .|. ((x .&. 1) `shiftL` 3)
