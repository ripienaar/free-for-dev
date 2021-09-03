#!/bin/bash
#
# Lint Markdown Files
#

MDL_OUTPUT=`mdl $GITHUB_WORKSPACE/INDEX.md -r MD011,MD039,MD022`

if [ ! -z $MDL_OUTPUT ]
then
  echo $MDL_OUTPUT
  exit 1
fi
