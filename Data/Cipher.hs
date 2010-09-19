{-# LANGUAGE FlexibleContexts, FlexibleInstances, FunctionalDependencies,
             GeneralizedNewtypeDeriving, MultiParamTypeClasses #-}

-- | This module provides support for block ciphers
module Data.Cipher
    (
    -- * Classes
    Cipher
    ,MonadCbc
    -- * Types
    ,Cbc
    ,CbcT
    -- * Functions
    ,encrypt
    ,decrypt
    ,evalCbc
    ,evalCbcT
    ,cbcEncrypt
    ,cbcDecrypt
    ) where

import Control.Monad.State
import Data.Bits

-- |Contains the result of an operation in the context of
-- cipher-block-chaining mode.
newtype Cbc c iv a = Cbc (State (c, iv) a)
    deriving (Monad, Functor)

-- |CbcT is the monad transformer version of Cbc
newtype CbcT c iv m a = CbcT (StateT (c, iv) m a)
    deriving (Monad, Functor, MonadTrans)

-- |Evaluates a cipher-block-chaining-mode operation, given
-- a cipher and an initialization vector (IV).
evalCbc :: Cbc c w a -> c -> w -> a
evalCbc (Cbc s) c iv = evalState s (c, iv) 

-- |This is the monad tranformer version of evalCbc
evalCbcT :: (Monad m) => CbcT c w m a -> c -> w -> m a
evalCbcT (CbcT s) c iv = evalStateT s (c, iv)

-- | A cipher
class (Bits w) => Cipher w c | c -> w where
    encrypt :: c -> w -> w
    decrypt :: c -> w -> w

-- | Any monad that contains the result of an operation in the
-- context of cipher-block-chaining mode.
class (Bits w, Cipher w c, MonadState (c, w) s) => MonadCbc c w s m | m -> c, m -> w, m -> s where
    monadCbc :: s w -> m w

instance (Bits w, Cipher w c) => MonadCbc c w (State (c, w)) (Cbc c w) where
    monadCbc = Cbc

instance (Bits w, Cipher w c, Monad m) => MonadCbc c w (StateT (c, w) m) (CbcT c w m) where
    monadCbc = CbcT

-- |This is the fundamental cipher-block-chaining encryption protocol
cbcEncrypt :: (MonadCbc c w s m) => w -> m w 
cbcEncrypt w = monadCbc $ do (c, iv) <- get
                             let w' = encrypt c (w `xor` iv)
                             put (c, w')
                             return w'

-- |This is the fundamental cipher-block-chaining decryption protocol
cbcDecrypt :: (MonadCbc c w s m) => w -> m w
cbcDecrypt w = monadCbc $ do (c, iv) <- get
                             let w' = decrypt c w `xor` iv
                             put (c, w)
                             return w'

