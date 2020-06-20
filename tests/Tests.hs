{-# LANGUAGE OverloadedStrings #-}
module Main where

import Imports

import qualified Hash
import qualified CBC

tests = testGroup "crypto-cbc"
    [ Hash.tests
    , CBC.tests
    ]

main = defaultMain tests
