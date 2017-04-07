# PAM Riemann client

## Introduction
[Riemann](http://riemann.io/) is a tool for data ingestion and processing. It is primarily devoted to network events, but it's heart, Clojure, makes it possible to use it also within other domains. Ons of them is *network security*. My contribution is a Linux PAM module, acting as a "silent" Riemann client. It detects any auth attempt and send the relative event to a Riemann configured server for data collection.

## Dependencies

## Build and Install

## Usage

## Credits
pam-riemann is a creation of [Luca Simone Ronga](https://github.com/rongals) (c) 2017
