module Main(main) where

import Data.Bits
import Data.Cipher
import Data.LargeWord
import Codec.Encryption.Twofish
import Test.HUnit


tfTest128 :: Test
tfTest128 = tfTest (\k b -> b) 
                   (0 :: Word128)
                   (0x21f9527982aa147e98c63345a524a7bc :: Word128)
                   48

tfTest192 :: Test
tfTest192 = tfTest  (\k b -> fromIntegral b .|. (k `shiftL` 128))
                   (0 :: Word192)
                   (0x4109640a86bd90a3f4f9ee2b214954e7 :: Word128)
                   50 

tfTest256 :: Test
tfTest256 = tfTest (\k b -> fromIntegral b .|. (k `shiftL` 128))
                   (0 :: Word256)
                   0x05a2973bc3f4ddf57561f61cff26fe37
                   50

-- |Test Twofish using the given test vectors in the Twofish
-- paper: a 128/192/256 bit key consisting of all zeroes, an
-- initial block consisting of all zeroes, and a known
-- final cipher text after 48 rounds
tfTest :: (Key a) => (a -> Word128 -> a) -> a -> Word128 -> Int -> Test
tfTest f k o r = TestCase $ assertEqual ("Key Size: " ++ show (bitSize k))
                                        o
                                        $ run k 0 1
    where run key block n
              | n < r     = let c = encrypt (mkStdCipher key) block
                            in run (f key block) c (n + 1)
              | otherwise = block

main = runTestTT $ TestList [tfTest128, tfTest192, tfTest256]

