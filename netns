#!/bin/bash
cp ~/.bashrc /tmp/temp.bashrc
echo "PS1=\"\$PS1[$1] \"" >> /tmp/temp.bashrc
[ -n "$TMUX" ] && tmux set-option -w pane-border-status top && tmux set -p @mytitle "netns $1"
sudo ip netns exec $1 sudo -u $USER -- bash --rcfile /tmp/temp.bashrc
