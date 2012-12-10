-- Module     : Main
-- Copyright  : (c) Ron Leisti 2010-2012
-- License    : BSD3
-- Maintainer : ron.leisti@gmail.com
--
-- |Various tests for the Twofish cipher, taken from the
-- Twofish paper.
-- <http://www.counterpane.com/twofish.html>
--
module Main(main) where

import Data.Array.Unboxed
import Data.Bits
import Data.LargeWord
import Codec.Encryption.Twofish
import System.Exit (exitSuccess, exitFailure)
import Test.HUnit
import Text.Printf

-- |A test, including intermediate steps, of 192-bit encryption.
test192_single_encrypt =
  let key = fromIntegral
              0x77665544332211001032547698BADCFEEFCDAB8967452301 :: Word192
      s   = mkS key
      h   = mkfH key
      k   = mkK key 16 h
      g   = mkG h s
      p0  = 0 `xor` k 0
      p1  = 0 `xor` k 1
      p2  = 0 `xor` k 2
      p3  = 0 `xor` k 3
      testRound :: (Integral a) => Int -> a -> a -> Assertion
      testRound n block0 block1 =
        let (r0, r1, r2, r3) = encryptRounds g k n (p0, p1, p2, p3)
        in do
          assertEqualHex (printf "Round %d word 0" n :: String)
                         block0
                         r0
          assertEqualHex (printf "Round %d word 1" n :: String)
                         block1
                         r1
  in TestCase $ do
    assertEqualHex "s 0 must match" 0x45661061 (s ! 0)
    assertEqualHex "s 1 must match" 0xb255bc4b (s ! 1)
    assertEqualHex "s 2 must match" 0xb89ff6f2 (s ! 2)
    assertEqualHex "k 0 must match" 0x38394A24 (k 0)
    assertEqualHex "k 1 must match" 0xc36d1175 (k 1)
    assertEqualHex "k 2 must match" 0xe802528f (k 2)
    assertEqualHex "k 3 must match" 0x219bfeb4 (k 3)
    assertEqualHex "k 4 must match" 0xb9141ab4 (k 4)
    assertEqualHex "k 5 must match" 0xbd3e70cd (k 5)
    assertEqualHex "k 6 must match" 0xaf609383 (k 6)
    assertEqualHex "k 7 must match" 0xfd36908a (k 7)
    testRound 1 0x9c263d67 0x5e68be8f
    testRound 2 0xc8f5099f 0x0c4b8f53
    testRound 3 0x69948f5e 0xe67c030f
    testRound 16 0x17738cd3 0xb5142d18
    let (f0, f1, f2, f3) = encryptRounds g k 16 (p0, p1, p2, p3)
    let c0 = f2 `xor` k 4
        c1 = f3 `xor` k 5
        c2 = f0 `xor` k 6
        c3 = f1 `xor` k 7
    assertEqualHex "c0 must match" 0xe5d2d1cf c0
    assertEqualHex "c1 must match" 0xdf9cbea9 c1
    assertEqualHex "c2 must match" 0xb8131f50 c2
    assertEqualHex "c3 must match" 0x4822bd92 c3
    assertEqualHex "final result must match"
                    0x4822bd92b8131f50df9cbea9e5d2d1cf
                    $ encrypt (mkStdCipher key) (fromIntegral 0)

-- | Encryption test with multiple iterations using a 128 bit key.
test128_iterative_encrypt :: Test
test128_iterative_encrypt =
  let key = fromIntegral 0 :: Word128
      block = fromIntegral 0 :: Word128
      run key block n
        | n > 0     = let c = encrypt (mkStdCipher key) block
                      in run block c (n - 1)
        | otherwise = block
      testIteration :: Int -> Word128 -> Assertion
      testIteration iteration expected =
        assertEqualHex msg expected (run key block iteration)
        where msg = printf "128 bit encryption iteration %d" iteration :: String
  in TestCase $ do
    testIteration 47 0x21f9527982aa147e98c63345a524a7bc

-- | Encryption test with multiple iterations using a 192 bit key.
test192_iterative_encrypt :: Test
test192_iterative_encrypt =
  let key = fromIntegral 0 :: Word192
      block = fromIntegral 0 :: Word128
      run key block n
         | n > 0     = let c = encrypt (mkStdCipher key) block
                           block' = fromIntegral block :: Integer
                           key'   = fromIntegral key :: Integer
                           key''  = (key' `shiftL` 128) .|. block'
                           key''' = fromIntegral key''
                       in run key''' c (n - 1)
         | otherwise = block
      testIteration :: Int -> Word128 -> Assertion
      testIteration iteration expected =
        assertEqualHex msg expected (run key block iteration)
        where msg = printf "192 bit encryption iteration %d" iteration :: String
  in TestCase $ do
    testIteration 1 0x0191c18f1760f85344bd6589781fa7ef
    testIteration 2 0x881e1a736dbb46b4365e106b70b2b288
    testIteration 3 0xb241a33c07dcb685d59749bad669da39
    testIteration 4 0x653a1929dcacdaf945ea9714d8022b18
    testIteration 9 0x78fc631263bd71350750c5987bd63f89
    testIteration 10 0x678f8e57b50087d5631a84c8c94f4316
    testIteration 48 0xb676fb8553be70ef21fa25113073abf0
    testIteration 49 0x4109640a86bd90a3f4f9ee2b214954e7

-- | Encryption test with multiple iterations using a 256 bit key.
test256_iterative_encrypt :: Test
test256_iterative_encrypt =
  let key = fromIntegral 0 :: Word256
      block = fromIntegral 0 :: Word128
      run key block n
        | n > 0     = let c = encrypt (mkStdCipher key) block
                          block' = fromIntegral block :: Integer
                          key'   = fromIntegral key :: Integer
                          key''  = (key' `shiftL` 128) .|. block'
                          key''' = fromIntegral key''
                      in run key''' c (n - 1)
        | otherwise = block        
      testIteration :: Int -> Word128 -> Assertion
      testIteration iteration expected =
        assertEqualHex msg expected (run key block iteration)
        where msg = printf "256 bit encryption iteration %d" iteration :: String
  in TestCase $ do
    testIteration 49 0x05a2973bc3f4ddf57561f61cff26fe37

-- | Asserts that two numeric values are equal, and if they are not,
-- reports the numbers using their hexidecimal representations.
assertEqualHex :: (Integral a, Integral b) => String -> a -> b -> Assertion
assertEqualHex message x y =
  let x' = printf "%x" (fromIntegral x :: Integer) :: String
      y' = printf "%x" (fromIntegral y :: Integer) :: String
  in assertEqual message x' y'

main =
  do
  result <- runTestTT $ TestList [test128_iterative_encrypt
                                  ,test192_single_encrypt
                                  ,test192_iterative_encrypt
                                  ,test256_iterative_encrypt]
  if (failures result > 0)
    then exitFailure
    else exitSuccess
        

