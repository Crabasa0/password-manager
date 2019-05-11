# password-manager
A password manager. Final project for AIT Applied Cryptography

Note: May have to change implementation for the "directory" file, as Pickle takes a file object and not a bytes object or String. Perhaps simpler to serialize ourselves. UPDATE: JSON is probably a better format for this, switching to that.

Other note: In the original design, deletion looks to be slow, difficult to implement, and error-prone. Recommend the following update: When an account is deleted, write over its blocks in the password file rather than delete them. Then remove the entry from the directory. Should be just as secure, but easier to implement and faster.

Big PM guy here, enjoy this text-based SCRUM board!

To do:

Retrieving details
Modifying an account
Deleting an account
Change master password

  


In progress:

Interfaces (stubbed out), 
Memory "safety",
Add an account


Complete: 
login,
setup,
random password generation


Topics to investigate:
memoryview as a method to directly access memory and avoid copying
