#!/bin/sh

mkdir output

pandoc -s README.md -o output/FREE_FOR_DEV.html
pandoc -s index.html -o output/index.html

echo "generated_at: $(date)" > variables.yml

mustache variables.yml index.output.html > output/index.html
mustache variables.yml README.output.md > output/README.md

echo "Done!"
