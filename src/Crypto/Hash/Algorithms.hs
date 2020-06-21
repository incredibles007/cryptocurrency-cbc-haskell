-- |
-- Module      : Crypto.Hash.Algorithms
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Definitions of known hash algorithms
--
module Crypto.Hash.Algorithms
    ( HashAlgorithm
    , HashAlgorithmPrefix
    -- * Hash algorithms
    , MD5(..)
    , SHA1(..)
    , SHA224(..)
    , SHA256(..)
    , SHA384(..)
    , SHA512(..)
    ) where

import           Crypto.Hash.Types (HashAlgorithm, HashAlgorithmPrefix)
import           Crypto.Hash.MD5
import           Crypto.Hash.SHA1
import           Crypto.Hash.SHA224
import           Crypto.Hash.SHA256
import           Crypto.Hash.SHA384
import           Crypto.Hash.SHA512
