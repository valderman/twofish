{-# LANGUAGE FlexibleContexts #-}
module Main(main) where

import Codec.Encryption.Twofish
import Control.Monad
import Data.Cipher
import Data.LargeWord

run :: (Cipher Word128 c) => Cbc c Word128 Word128
run = fmap f d
    where d = forM [0..10000] $ \i -> cbcDecrypt (fromIntegral i) 
          f = foldl (+) 0

main = do let x = evalCbc run (mkStdCipher (0xff00ff :: Word128)) 0xaabbcc
          putStrLn . show $ x

