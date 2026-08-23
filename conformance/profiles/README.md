# EITT profiles

Profiles are grouped by the stack implementation under test:

- `full/` drives `zweidraehte-device` DUTs.
- `micro/` drives polling `zweidraehte-microdevice` DUTs.

A profile describes one concrete DUT composition. Security remains a
composition choice, not a mask-family alias: for example the secure BCU2
profile happens to use mask 0021h, but its Data Secure requirements come from
the selected module.
