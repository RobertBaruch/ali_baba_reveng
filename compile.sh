#!/bin/bash -e

rm output/main.*
python -m weave
pdflatex --output-directory=output output/main.tex
pdflatex --output-directory=output output/main.tex
