{-# LANGUAGE OverloadedStrings #-}
module Main where

import Imports

import qualified Hash

tests = testGroup "crypto-cbc"
    [ Hash.tests
    ]

main = defaultMain tests
