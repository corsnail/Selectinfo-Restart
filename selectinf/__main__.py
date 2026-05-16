# -*- coding: utf-8 -*-
"""
Entry point for `python -m selectinf`

Equivalent to running `python run.py` from the project root.
The run.py module lives at the project root (sibling of selectinf/),
and is importable because Python adds the script directory to sys.path.
"""
import run

if __name__ == "__main__":
    run.main()
