# EITT patch ownership

The first directory level names the stack implementation whose observable
behavior requires the patch. `full/common` is common only to the full-stack
System B and System 7 fixtures; it is not a global dumping ground.

Micro fixtures own separate family patch sets. A small duplicated adaptation
is preferable to making a change for one stack silently alter another stack's
test contract. Within a family, split files by template collection when their
reasons differ, as with BCU2 AN158 and AN177.
