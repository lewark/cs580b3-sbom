#!/bin/sh

if [ ! -d chroma_data ]; then
	mkdir chroma_data
fi

chroma run --path $PWD/chroma_data
