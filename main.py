import intro
import interface
import sys
from os import system, name

if __name__ == '__main__':
    # start intro animation
    s = intro.Animate()
    s.start()
    # initialize cmd interface
    i = interface.LuckyHammer()
    # Windows Support
    if name == 'nt':
        system('cls')
    # Nix support
    else:
        system('clear')
    # exit program on cmdloop exit
    sys.exit(i.cmdloop())
