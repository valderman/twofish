module Data.Bitlib (
   pack
  ,packMany
  ,unpack
  ,unpackMany
) where

import Data.Bits

pack :: (Integral a, Bits a, Bits b) => [a] -> b
pack []     = fromInteger 0
pack (x:[]) = fromIntegral x
pack (x:xs) = (fromIntegral x) .|. ((pack xs) `shiftL` (bitSize x))

unpack :: (Integral a, Bits a, Bits b) => a -> [b]
unpack = doUnpack 0
    where doUnpack :: (Integral a, Bits a, Bits b) => Int -> a -> [b]
          doUnpack n x
              | n == bitSize x = []
              | otherwise      = (fromIntegral (x .&. 0xFF)) : doUnpack (n + 8) (x `shiftR` 8)

packMany :: (Integral a, Bits a, Num b, Integral b, Bits b) => b -> [a] -> [b]
packMany _ []          = []
packMany zero xs@(x:_) =
    let ct = (bitSize zero) `div` (bitSize x)
    in pack (take ct xs) : packMany zero (drop ct xs)

unpackMany :: (Integral a, Bits a, Bits b) => [a] -> [b]
unpackMany []     = []
unpackMany (x:xs) = concat [(unpack x), (unpackMany xs)]
