#!/bin/bash

chmod +x client
mkdir -p ~/bin
cp client ~/bin
chmod +x ~/bin/client
export PATH=$PATH":$HOME/bin"