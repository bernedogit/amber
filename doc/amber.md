Amber
=====

This file deals with the use of the program *amber*.

You can use *amber* to encrypt and decrypt files using either symmetric or
public key algorithms. It can also be used to sign and verify files using
public key algorithms.

This document is intended for people using the amber program. It provides some
introduction to the basics of cryptography. This is required to understand
how to use some features and why they are there. Most of the functions
carried out by this program are actually implemented as a library. See the
documentation and source code of the library for details on using the library.

In order to simplify the explanation for novices we refer in this document to
public keys as padlocks, private keys as keys and key signatures as
certificates. We refer to symmetric key encryption as password based
encryption. We refer to public key encryption as padlock based encryption.



Basics of Cryptography
======================

Services provided
-----------------

There are some typical use cases in cryptography. Alice wants to send a
message to Bob. Eve is listening to the conversation between Alice and Bob.
Alice and Bob want to prevent Eve from learning the contents of their
conversation. Therefore they use encryption to achieve **confidentiality**.
Confidentiality means that the contents of the message remain secret to
unauthorized persons.

If Eve just listens to the conversation then she is a *passive* eavesdropper.
However there is another malicious actor, Mallory, who has the ability to
interfere with the communication. For instance she may shout so loudly that
neither Alice nor Bob will hear each other. This would be a case of denial of
service.

Mallory may also interfere in other ways. Assuming that Alice and Bob are
exchanging letters which are encrypted, Mallory may intercept the letter from
Alice, modify it and send the modified letter to Bob. If the encryption
scheme offers only confidentiality, Mallory will not learn the plain text
contents of the message, but she may modify the encrypted message. When Bob
decrypts the modified messsage he will decrypt it and get something that is
different from the original message. Although Mallory does not know what was
in either the original message or in the modified message, she has been able to
modify it. Some encryption systems also provide **authentication**.
Authentication detects any tampering that Mallory may have done. With
authentication Bob will detect that the message is not the original one
created by Alice. For a system to be used reliably you must have both
confidentiality and authentication. *Amber* provides confidentiality and
authentication.

Another service that is also required from cryptography is signing messages.
Alice may sign a message and send it to Bob. Bob receives the message and can
verify that it was indeed signed by Alice. Furthermore he can show the
message to Carol and Carol can verify that the message was indeed signed by
Alice. Whereas confidentiality and authentication are used together,
signatures are likely to be used with unencrypted documents. If the signed
message is a contract, Bob wants to be able to prove to a judge that Alice
signed the message without having to reveal his own private key.



Types of encryption
-------------------

For the purposes of this description we divide encryption algorithms into two
categories, password based algorithms and padlock based algorithms. In
password based algorithms you use the same password to encrypt and to
decrypt. Therefore the sender and the receiver must share the secret password
before they can send messages to each other. Because anyone with the secret
password can decrypt the message, the password must remain secret. Therefore
password based algorithms are also called secret key algorithms. They have
the problem that the shared password must be distributed in advance through
secure channels. This means that Alice and Bob must meet in person without
Eve noticing and exchange the secret password carefully.

Padlock based algorithms use a padlock and a key. Bob builds a padlock and the
corresponding key. He unlocks the padlock and sends the unlocked padlock to
Alice. Alice puts a message into a box and locks the box with the padlock by
closing the padlock. The padlock can now be opened only using Bob's key. In
this way Bob does not need to send any secrets in the open. He just sends the
unlocked padlock. In the same way Alice manufactures her padlock with her
corresponding key. She sends her unlocked padlock to Bob. When Bob wants to
send a message to Alice, he puts the message into a box and locks the box
with the padlock he got from Alice. Now only Alice can open the padlock with
her key.

In this example Alice and Bob would have to manufacture a new padlock for
each message. In digital cryptography both the padlock and the key are just a
string of characters. Once that you get the digital padlock you can reuse it
as many times as you want. Bob only needs to send his digital padlock once
to Alice and she can reuse it as many times as she wants. Eve can listen to
the exchange and learn the values of the digital padlocks of Alice and Bob.
She also knowns the encrypted message, but cannot decode the message because
she would need the private key of Bob. A digital padlock is just a string of
characters like this:

	NsHUUS5u5Hfukj3MKeN5NR3SnjfdueVRkJrg2wKQmdyLd


Using padlock and key algorithms the problem of distributing the padlocks is
simplified. Alice and Bob can publish their digital padlocks and store them
in a public directory. Anyone who wants to send messages to Alice or Bob can
just look up their digital padlocks in the directory. Of course we must
ensure that the padlock which is listed under Alice's name belongs indeed to
Alice. This later problem, attaching mathematical entities (digital padlocks)
to people's identities cannot be solved with just mathematics and needs
protocols like the public key infrastructure certificates or PGP's web of
trust.

Amber ensures that if Alice encrypts a message using Bob's padlock then only
Bob's key can decode them. Furthermore amber also guarantees that when Bob
decrypts the message, then the sender of the message is identified. If amber
says that Alice wrote the message then Bob can trust it. However Bob cannot
prove to any other person that the message was sent by Alice. This is a
feature of amber and allows the sender of the message to deny to third
parties that she wrote the message. If the message was a contract, Bob knows
that it was sent by Alice but he cannot prove to a third party that Alice
sent the message. In this case we need a signature.

The signature scheme also uses the padlock and the key. Each key has a seal
that can be used to sign documents. The padlock corresponding to the seal has
an image of the imprint produced by the seal. Only the owner of the seal can
create an imprint. Therefore whenever the you see the imprint that matches
the image on the padlock you know that the owner of the corresponding key
signed it. As before this is only an analogy. In the digital realm the
padlock and the imprint are the same string of 32 bytes and the key and the
seal are just another 32 byte string.

Alice signs messages with her private key and publishes the signature and her
public padlock. Anyone can verify that the message was indeed signed with the
private key corresponding to the known public padlock. This solves the
problem of repudiation.

You use secret password algorithms to encrypt files that you keep in your
computer or in some cloud storage. You use a password to encrypt the file and
the same password is used to decrypt it. You do not need to share the
password with anyone. For such usage password-based encryption ist best
suited.

If you need to exchange messages with somebody else it is better to use
padlock based algorithms. You just publish your public padlock.
Anyone can send encrypted files to you using your public padlock, but only
you can decrypt them. Only you can sign files using your private key but
anybody can verify that you signed the files if they have access to your
public padlock.

Note that the padlock and key is just an analogy to make it easier to
understand. In cryptography they are named public key and private key
respectively and the use of padlocks and keys is referred to as "asymmetric
cryptography" or "public key cryptography".



Padlock distribution
--------------------

Whenever you create a pair consisting of a digital padlock and its key you
must distribute the padlock to all people who may want to send messages to
you. You keep the key with you and do not let anyone have access to it. The
program takes care of storing the private key in files that have been
encrypted with a password based algorithm. Therefore even if somebody steals
your private key files, they still need to know the corresponding password in
order to get access to the private keys.

The algorithms just establish the match between a padlock and its
corresponding key. They do not entirely solve the problem of padlock
distribution. Directly sending public padlocks through open channels like
e-mail is safe against passive eavesdroppers but fails when there is a
man-in-the-middle attack (MITM). A MITM attack works like this: Alice sends a
note to Bob. The note contains her public padlock. Mallory is sitting between
Alice and Bob and intercepts the note. Mallory keeps the public padlock of
Alice for herself, but creates a new padlock and key pair, *Kb*, and puts the
padlock of *Kb* in the note and forwards it to Bob. Bob receives the note and
thinks it comes from Alice, but it really contains Mallory's padlock of *Kb*.
Bob then sends his padlock to Alice in a note. Mallory intercepts this note.
Mallory creates a new padlock/key pair, *Ka*, and writes the padlock of *Ka*
in the note and forwards the note to Alice. Now both Alice and Bob think they
have each other's padlocks but they only have Mallory's padlocks. Alice sends
a secret message to Bob using what she thinks is Bob's public padlock. Mallory
intercepts the message, decrypts it (it was encrypted for the key *Ka*),
reads it and encrypts it with the key *Kb*. Mallory finally forwards this
message (the one encrypted with *Kb*). Bob gets the message and sees that it
has been encrypted with the key *Kb* which he thinks belongs to Alice. If
Mallory does this game for all messages that Alice and Bob exchange, they
will never know that they are really talking to Mallory. This is the MITM
attack.

Also somebody may attempt to impersonate you and distribute their padlock
pretending that it is your padlock. The public key infrastructure attempted
to solve this but has failed in practice. The web of trust approach used by
PGP seems better but it is also cumbersome.

This program does not attempt to solve the padlock distribution problem
because it can't. It expects that you somehow get the public padlocks and
that you verify that the padlocks are authentic. This may be done by getting
the padlocks in person or by having somebody else that you trust sign the
padlocks. Given that the padlocks used by this program are quite short it
should be possible to easily distribute them. The program offers some
facilities to certify padlocks and to have master and work padlocks. These
features simplify the management and distribution of padlocks.

Once you get the padlocks from somebody you can just append them to the key
ring file and can use them. In case that a padlock is revoked you would need
to delete it from the said file.



Security properties
-------------------

The program always checks that a decrypted message has not been tampered
with. You can rely on this if you need the assurance that the message has not
been modified by somebody else. For instance if Alice uses the program to
send a message to Bob and Bob decrypts it succesfully, then Bob knows that
the message has not been altered and that the message could be created only
by somebody who has Alice's private key. If Alice's private key is known only
to Alice then Bob can be certain that Alice wrote that message. On the other
hand although Bob knows that Alice wrote the message he cannot prove that to
anyone, even if he shows his own private key. This is because Alice and Bob
share a secret (created by combining the keys of Alice and Bob) and any of
them can create that message and it will still be accepted as valid. This
property applies even if you encrypt a message for multiple recipients.

The program has an option to create a spoofed message. Bob creates an spoofed
message by using his padlock and key and Alice's padlock so that it looks
like if it was encrypted by Alice. Bob can decrypt this message and the
program will tell him that it was encrypted by Alice. Imagine that Alice and
Bob are coworkers and that they exchange messages criticizing their boss. Bob
could take a message written by Alice, show the boss his private key and show
the message to the boss. The boss would use Bob's private key and see himself
that Alice wrote it. However amber has been designed to allow Alice to deny
that she wrote it, because Bob could also have created such a message.

When Bob receives a message from Alice he knows that only Alice or himself
could have created the message. Only Alice or Bob could have created the
message. Alice would create it using the normal options and Bob could have
created it using the spoofing option. Bob knows whether or not he created the
message. If he didn't spoof the message then he knows that the message came
from Alice. However if Bob wants to show to his boss that Alice sent the
message, Alice can always say that she didn't write that text and that Bob
spoofed the message. In terms of cryptography amber provides authenticity and
repudiation. As seen in the example above repudiation is a desireable
property when exchanging secret messages.

Assume that Alice uses amber to encrypt a message for Bob and Carol. Only a
single message will be encrypted, not two. Any of Bob or Carol can decrypt
the message using their key. Nobody else can decrypt the message. Nobody else
can figure out who sent the message or who can decrypt it. Bob can check that
the message was addressed to him and that it was indeed created by Alice.
Carol can also check that the message was addressed to her and that Alice
wrote it. But Bob cannot figure out if Carol can also decrypt the message.
Neither can Carol figure out if Bob can decrypt the message. Each of the
recipients knows that they can decrypt the message but they do not know who
else can also decrypt it. Without access to the key of one of the recipients
Eve cannot even know who encrypted the message or to whom it is addressed.

Each recipient gets a guarantee that the sender encryted the message for
them. However they cannot prove that to any third party. Amber has been
designed to provide the guarantee only to the recipient, but not to somebody
else.

If Bob needs to prove to Carol that Alice sent the message then Alice must
sign the plain text with her key. Signatures provide for non repudiation:
Alice cannot later pretend that she did not sign the message.

You must consider carefully what you need: confidentiality, authentication or
non-repudiation. If Alice and Bob are exchanging secret messages that would be
embarrassing to them, they should use confidentiality and authentication but
not signatures. Alice and Bob know that the other one sent the message but if
their messages are discovered they can pretend that they didn't write the
messages and that the other one, either Bob or Alice, actually spoofed the
messages. This is what you usually want when sending secret messages.

On the other hand sometimes you may want to make it public that you wrote a
message. For instance you may want to ensure that third parties can verify
that you wrote a message. In this case you do not want confidentiality but
you use signatures.

In general when using confidentiality (encryption) you just want
authentication. When using signatures you usually do not want
confidentiality. If you think you need confidentiality and non-repudiation
(signatures) then think twice because it is likely that this is not what you
really want.

You must consider that this program provides only for the cryptographic part
of security. If there is a virus in your computer it can read anything that
you write before it is encrypted. Therefore the first thing (and more
difficult than using any encryption program) that you must do is to ensure
that your computer has not been infected by malware.

Even if you are using a clean computer and correctly using the program there
are other means that Eve can use to gather information about you. The mere
fact that you are sending e-mail to somebody already gives a lot of
information. It may not matter much if the actual messages are encrypted: if
somebody in company A is exchanging lots of e-mails with somebody in the
competing company B then it looks like one of them is passing secrets to the
competition. Confidentiality only ensures that nobody knows which secrets are
being passed, but this is not as important as knowing that somebody is leaking
secrets.

The encrypted files created by the program cannot be distinghished from a
file filled with random bytes if you do not have the decryption key or
password. There is no way for an outsider to tell if the file has just random
bytes or an encrypted message.


Traffic Analysis
----------------

In the introduction we have established that Eve is listening to the
conversation between Alice and Bob. Eve can see that Alice and Bob are
talking although she cannot decrypt the contents. Eve can however measure the
amount of encrypted traffic that they are exchanging and she can also observe
variations over time in the amount of encrypted traffic. Alice can make Eve's
task more difficult by padding the messages before encryption with random
bytes. To Eve both the message and the padding look the same and she cannot
distinguish them. Alice could pad all her messages with a variable number of
random bytes. In this case Eve would see a series of encrypted messages of
variable lengths, with the length of the encrypted message bearing no
relation to the actual length of the plain text message.

The program pads encrypted messages with a variable number of random padding
bytes. If Eve modifies the padding bytes the program will detect it in the
same way as if the actual message was tampered with.

Every time that you encrypt the same message amber will create an encrypted
file of a different length. If it didn't it would be easier for Eve to figure
out what is being communicated. Imagine that Alice needs to send a yes or no
message to Bob. If there weren't any padding an encrypted message of length 3
would tell Eve that a YES was sent. Similarly Eve could infer that an
encrypted  message of length two implies that a NO has been sent.



Key management
--------------

Key management is one of the weakest parts in a cryptosystem, together with
the random number generator and the general protection of the computer from
malware. In theory you create a pair consisting of a padlock and a key. You
store the private key in a safe place and you distribute the padlock. There
are several problems with this simplistic view.

The first problem is that Alice must distribute her padlock to all parties
that may want to send encrypted messages to her. She could just post it
somewhere, but there is a risk that Mallory posts her padlock pretending that
it is actually the key of Alice. The best way to solve this is getting the
padlock in person from Alice. If Bob cannot get Alice's padlock directly from
her then he could get the padlock from somewhere else (for instance a web
page) and then call Alice to verify that the bytes of the padlock are indeed
those of Alice.

Another method would be to use a trusted common friend, Trent, to certify
that the padlock really belongs to Alice. Amber provides the option to certify
padlocks. For instance the boss of Alice, Bob and Carol can certify their
padlocks with his own private key. By certifying a padlock the certifier is
stating that he guarantees that the padlock belongs to the person whose name
is written on the padlock. When Alice gets a padlock from Bob she checks to
see if the padlock has been certified by their boss. If it was, then she
trusts that the padlock indeed belongs to Bob, because the boss has certified
it. With this scheme we trust the padlock if we trust whoever certified it.
Amber supports having multiple certificates attached to a single padlock.
However it does not interpret them in any way. It is up to you to decide if
you trust the certifiers of the padlock. Amber just shows them to you and you
decide whether you want to add the padlock to your key ring or not.

We have considered that Alice creates her padlock and distributes it once and
that's all. However private keys get lost or stolen. If Eve steals a private
key then she can decrypt all messages that were encrypted for that key. We
can minimize the consequences of key compromises by changing keys frequently:
a compromised key would allow decrypting the messages that were encrypted for
that key but not messages that were encrypted for other keys. Therefore we
must plan that the keys will be compromised and that they must be changed
often. This provides forward secrecy. However we do not want to repeat the
whole effort listed above to distribute authentic padlocks.

We must also consider the security of the private keys. We must use our
private keys when we decrypt messages sent to us and we must use our private
keys to sign messages. If we use the private keys daily it will be difficult
to keep them safe.

There is a better approach to solve the problems listed above. Alice should
create a master padlock/key pair that is used only for certifying other pairs.
The padlock part of Alice's master pair is distributed once widely using the
secure methods mentioned above. Alice also stores the private key offline in
some secure carrier like a piece of paper locked into a vault. The private
part of the master key will be seldom used. For every day use, Alice creates
work padlock/key pairs that are changed periodically. Every time that she
creates a new work pair, she certifies the padlock part of the pair with her
master key. She then distributes the certified padlock using any convenient
insecure channel. When Bob gets the certified padlock from Alice he will
first verify the certificate using Alice's public master padlock. If it
passes then it means that this padlock was indeed certified by Alice and is
authentic. He can then use the new padlock for all messages intended for
Alice.

The master key is used only to certify padlocks. All encryption and
signatures are done using the work keys. Therefore Alice needs to use her
master key very few times (only when a work key is created) and can keep her
master key safely locked offline most of the time. The master padlock/key
pair is what establishes the authenticity of the padlocks of Alice and only
the padlock part of the master key must be distributed with care.

At any time Alice will have just two keys active: her master key, which will
be used only to sign other keys, and her current work key. The current work
key will be used to encrypt and sign messages.

The program supports this method of key management by distinguishing between
master padlock/key pairs and working padlock/key pairs. You create a master
pair using the `--gen-master` option and cretate working pairs using the
`--gen-work` option. It displays master pairs with a 'M' apended to the
padlock. Working pairs are shown with a 'W' apended to the padlock. The
working pairs based on a master pair share the same name as the master
pair. When choosing a padlock or key it will choose the latest key, which
will be the most recent working key.



Signing
-------

The description above works well for encryption and decryption: you use the
current working padlock to encrypt and the current working key to decrypt.
Older padlocks and keys are retired and if anyone tries to use them then it
means that Mallory is trying to fool us. We can always require that whoever is
sending us messages is using the current key and not some key that has
already been retired. This scheme is not directly applicable to signatures.

When we get a signed document we may also require that it has been signed
with a current key. If we are expecting that we receive such signed documents
shortly after they have been signed this is a reasonable expectation. We
would just reject signatures which appear to have been created using a key
that has been retired.

In some cases the signatures are expected to be long lived. For instance I
may sign a document and expect that the signature remains valid years after
it was created. In the meantime the key used to sign the document may have
been replaced by a new one. There are three ways to handle this case:

We may require that keys used for signing are not retired. We effectively
state that once a key is used for signing then it remains valid forever. This
also implies that if Bob wants to be able to verify documents signed by Alice
he will need to store in his key ring all the keys that Alice has ever used
to sign documents, not just the current one. This may be difficult: if Alice
has replaced her keys and we ask her for her padlocks she will give us her
master padlock and the current working padlock, not the old retired padlock.

A variation of the above case is to use only the master key for signing. This
is what PGP/GPG does for key certificates: they can be signed only by the
master key of the certifier. Given that master keys never expire and are
always valid then the certificates continue to be valid. There is a problem:
if we always use the master key for signing and we often sign documents then
we are increasing the chance for the master key to be stolen. We are therefore
defeating the main advantage of having working keys. It is reasonable to
require certificates to be signed with the master key because creation of
certificates will be a rare event. However it does not seem reasonable to
require using the master key for every day signing.

We support an intermediate solution: signing with working keys with
certificates attached to the signature. In this case we sign documents with
the current working key. We also add to the signature the name of the signer,
the self signature of the padlock by the signer and any certificates that are
available for this padlock and key. When Bob wants to verify the signature he
will first check if the padlock corresponding to the key that signed the
document can be found in his own key ring. If it is there then it means that
the document has been signed with a key corresponding to a padlock that is
known to Bob and that he trusts (because it is in his key ring).

If the signing padlock could not be found in Bob's key ring then the self
signature will be verified and any attached certificates will also be
verified. The program will tell Bob that the padlock is not in his key ring
and therefore he does not yet trust it. However it will show the valid
certificates attached to the signature. Bob may see that the padlock has been
certified with Alice's master key. He then may conclude that he will trust
the signing padlock because he trusts Alice's master key.

We verify not only the certificates but also the self signature of the
signing padlock. The reason is that if Alice signs a document with her key,
Mallory could take Alice's signature and change the name embedded in the
signature to her own name. Mallory would then remove the existing
certificates from the signature and add her own certificate certifying that
the key belongs to Mallory. If we only check Mallory's certificate we may
conclude that the signature was produced by Mallory. However the document was
signed by Alice and not Mallory. Mallory may not even have access to the
document. If we check the self signature then we are ensuring that the name
written on the padlock is really the name given by the owner of the
corresponding key. Mallory could not pretend that she signed the document
without actually having the document.

Of course, if Mallory has access to the document she could fake a signature
by Alice. Mallory could create a working padlock/key pair and put Alice's
name on it. Given that Mallory owns the key she can self certify this key.
She then signs the document and attaches a certificate by Mallory stating
that the key belongs to Alice. The program would say that it seems that Alice
signed the document because Mallory certifies that the key belongs to Alice.
There are two solutions to this problem: accept only certificates in
signatures that have been produced by the same owner as the signing key, or
do not trust Mallory for cross certifications.

In the normal setting we would sign with the current working key and the only
certificate present in the signature would be the one created with the
corresponing master key. In this case both names are identical and we trust
the signature if we trust the master key. If we require recent keys for
encryption but use this scheme then we are stating that retired keys continue
to be valid for signatures even if they can no longer be used for encryption.
Note that the signing date embedded in the signature is the date according to
the computer running the program. If Mallory steals a key that has been
retired she could create back dated signatures and there would be no way of
detecting that they have been back dated.



Deniable encryption
-------------------

The concept of deniable encryption is that you may encrypt two files into a
single ciphertext with two different passwords. If you are forced to decrypt
the encrypted file then you can use the first password and it will decrypt
the encrypted file into the first plaintext file. However there is a second
file hidden in the encrypted file that can only be decrypted using the second
password. There is no way for somebody who only has the first password to
figure out if there is a second encrypted file.

Imagine that Bob works for Alice and has written a bunch of bad things about
Alice. He has encrypted the compromising text together with another, more
neutral text, say some bank account information, in an encrypted file. Alice
suspects that Bob has damaging information in the encrypted file and orders
him to give her his password so that she can decrypt the file. Bob has no
other option than complying. He gives the first password, which Alice uses to
decrypt the file. She obtains the information about the bank account. It is
reasonable for Bob to pretend that he had to encrypt the bank account
information. Furthermore it is not incriminating him. The second file is
still in the encrypted file but Alice cannot decrypt it or even know that
there is a second file without having the second password. In this way Bob
can comply with the decryption order and still keep the real secret file
secret. All files encrypted with this program and library have the potential
to hide a further file. This ensures that Alice will never know for sure if
there is an additional hidden file.

The program and library supports deniable encryption with two passwords as
shown above and also with two padlocks/keys. When encrypting two files using
padlocks, you use the first padlock to encrypt the bogus text. The second
padlock will be used to encrypt the real hidden text. To decrypt the real
hidden text you must supply the key corresponding to the first padlock and
also the key corresponding to the second padlock.



How to use amber
================

Functions
---------

Amber provides the following functions:

- Encrypt and decrypt files with a password.

- Encrypt and decrypt files with padlocks and keys.

- Encrypt and decrypt sets of files into an archive with a password.

- Encrypt and decrypt sets of files into an archive with padlocks and keys.

- List contents of encrypted archives and decrypt individual files from the
  encrypted archive.

- Sign a file and place the signature in a different file. The signature
  includes an optional signed comment.

- Sign a text file and append the signature at the end of the file, producing a
  clear signed text file. The signature includes an optional signed comment.

- Take a clear signed file which has been modified and update the signature
  to reflect the new contents.

- Verify signed and clear signed files.

- Create spoofed messages in order to support repudiation.

- Encrypt two files into a single encrypted file to support deniable
  encryption.

- Manage padlocks collected into key rings.

- Add, remove and verify certificates added to padlocks and keys.

- Export and import padlocks and keys.

- Special operation mode without using key rings. In this mode you must
  supply in the command line the public padlock of the recipient. Your own
  padlock and key are derived from a password.



Amber takes from the command line the names of the files to process and also
some options about what to do. Short options consist of an hyphen followed by
a letter, sometimes followed by further information. Short options which do
not take arguments can be grouped together. For instance the options -f and
-w can be written together as -fw. Long options start with two hyphens. They
may be followed by an argument. The argument may be separated from the long
option with spaces, with an equal sign or with a colon.

The list of options that are available is listed next.

General help
------------

-h or --help will show the list of available options.


Options concerning the management of keys
-----------------------------------------

`--ringless`

Do not use a key ring, but derive our key from the password. In this mode the
key ring file will not be read. Instead whenever your own key is required you
will be asked for a password and the password will be used as private key. In
this mode public padlocks will have to be entered directly using their base
58 encoding. You use the `--lockid` option to specify the recipients of the
message.


`--keyring` *file*

It specifies the name of the file containing the keys and padlocks. If the
name of this file ends with `.cha` it will be interpreted as a key ring file
encrypted with a password and you will be asked to supply a password to read
the key ring. If no keyring file is given then `amber.keys` or
`amber.keys.cha` will be used.

`--gen-master` *name*

Generate a new master key and padlock pair for the given name. The names
should follow the PGP conventions: Name <email-address>. For instance `"Bob
Builder <bob@builder.com>"`. The new padlock and key pair will be inserted
into the key ring.

`--gen-master` *name* --master *file*

Generate a new master key and padlock pair for the given name. The names
should follow the PGP conventions: Name <email-address>. For instance `"Bob
Builder <bob@builder.com>"`. The public padlock will be inserted in the
keyring and the private key will be written to the file *file*. The file
*file* has the same format as a keyring. Specifying the `--master` option
allows you to store the private key in another file and keep only the public
padlock in the key ring that you use every day.

`--gen-work`

Generate a working key. If there is a single master key in the ring then it
will be used. If there are several then you must specify which master key
will be used by using the `-u` option. If there are no master keys in the key
ring and the master key is stored in another file called _masterkey_ then you
must specify this file by using the option `--master` _masterkey_.

`--master` *masterfile*

Specify the name that contains the master key. When generating a new master
key the file *masterfile* will contain the master key. Only the master
**padlock** will be stored in the key ring, not the master **key**. When
performing other operations the keys in *masterfile* will be read and used as
if they were in the key ring.

`--keyfile` *keyfile*

Read the keys stored in the file *keyfile*. When performing operations on
keys these keys will be treated as if they were in the key ring.

`--export` *file*

Export the selected padlocks to the file *file*. Only the padlocks and their
certificates will be exported but not the corresponding keys (if available).
You can select padlocks using the `-r` or `-p` options.

`--export-sec` *file*

Export the selected padlocks and keys to the file *file*. Both the padlocks,
keys and their certificates will be exported to the given file. You can
select padlocks and keys using the `-r` or `-p` options.

`--import` *file*

Import padlocks and keys from the file *file*. Any padlocks and keys present
in the file will be read and merged with the existing key ring. If a padlock
or key is already present in our key ring then only the certificates that are
not already present in our key ring will be added.

`-f`

Force replacement of existing keys with imported ones. Use this option
together with the `--import` option to replace keys that are in the key ring
with the ones read from the imported file.

`-p` *name*

Select padlocks and keys matching the given *name*. This option can be given
multiple times. The name can be any word within the `name` and `alias` fields
of the padlock or key. The *name* can also be a starting sequence of the base
58 encoding of the padlock.

`-r` *name*

Select padlocks or keys matching this name. This option can be given multiple
times. The name can be any word within the `name` and `alias` fields. It can
also be the starting sequence of the base 58 encoding of the padlock. If both
master and work versions of the same name are available then choose the work
version. If there are several work versions then select the one most recently
created.

`--lockid` *padlock*

Interpret the padlock *padlock* as the raw encoding. This option allows you
to use keys which are not present in the key ring.

`--all`

Select all padlocks and keys present in the key ring.

`--delete`

Remove the selected keys or padlocks from the key ring. You select keys and
padlocks using the `-r` option.

`--rename` *name*

Change the name of the selected keys or padlocks to *name*. Note that this
will invalidate any certificates that may be present in the key.

`--alias` *name*

Change the alias of the selected keys or padlocks to *alias*. This does not
invalidate any certificates. Certificates only certify that the name
corresponds to the key, not the alias.

`--app-alias` *name*

Append the alias to the selected keys or padlocks. The existing aliases will
be kept and *name* will be added to the aliases for the selected keys.

`--add-raw`

Add a padlock using the raw base 58 encoding. The first argument in the
command line is the name of the owner of the padlock. The second argument is
the padlock's raw base 58 encoding.

`--add-raw-sec`

Add a private key using the raw base 58 encoding. The first argument is the
name of the owner of the key. The second argument is name of the file that
contains the key's raw encoding.

`-k`

This option will show the padlocks that are available together with their
names and aliases, if any.

`--list`

This option will show the padlocks and their certificates.

`--list-sec`

This option will how even the padlocks, their certificates and their secret
keys, if the latter are available.

`--list-file` *file*

This option will show the padlocks and keys that are stored in the given
file. The given file and the keyring will be searched to provide the names of
the certifying keys.

`--certify-by` *certifier*

Certify the selected padlocks. The key of the certifier will be looked up in
the key ring and it will be used to certify the selected padlocks. You select
padlocks using the `-r` or `-p` options. By certifying a padlock you are
saying that the padlock really belongs to the person whose name is mentioned
in the padlock. Other people will check the certificates and if they see that
you have certified a padlock and they trust you they will believe that the
padlock indeed belongs to the person whose name is written on it.

`--rm-cert` *certifier*

Remove the certificate given by the key corresponding to *certifier* from the
selected padlocks.

`--certify-lockfile-by` *certifier*

Use the private key of *certifier* to certify all the padlocks present in the
file whose name is given in the first argument.

`--check`

Check the consistency of the key ring. Any certificates which are wrong will
be detected.

`--correct`

Check the consistency of the key ring and remove the wrong certificates.

`--hex`

Show padlocks and keys in hexadecimal. By default we use base 58 encoding.

`--icao`

Show padlocks and keys in base 32. This is a case insensitive encoding.


Options concerning the operation
--------------------------------

`--passfile` *file*

Read the password from the file *file* instead of asking the user.

`-o` *outname*

Write the output to *outname*. Otherwise when encrypting the same name as the
input file will be used but with `.cha` appended to it. If you want to send
the output to stdout then use `-o-`.

`-u` *name*

Specify the name of the encrypter or signer.

`--uraw-file` *rawfile*

The private key that will be used is stored in the file *rawfile*. The
program will read the key from the file and use whenever a private key is
required. This allows you to use private keys that are not stored in the key
ring.

`--uraw`

The program will ask for the raw encoding of the private key. This allows you
to use private keys that are not stored in the key ring.

`-a`

Anonymous sender. Do not use any real key present in the key ring. The
recipient of the message will not know who sent it. It could be Alice, but it
could also be Eve. The recipient will be informed by amber that the sender
remains anonymous.

`-e`

Encrypt using padlocks. You must supply the name of the encrypted by using
the `-u` option and the names of the recipients by using the `-r` option.
Each file in the input will be encrypted.

`-c`

Encrypt using a password. You will be prompted to supply a password.

`-C`
`--dc`

Decrypt a file that has been encrypted with a password. The program will ask you
for the password.

`-E`
`--de`

Decrypt a file that has been encrypted with a padlock. You must name the key
corresponding to that padlock.

`-s` or `--sign`

Sign the first file given in the command line and put the signature in the
second file. You can supply optional comments in the third argument of the
command line. The optional comments will be signed and attached to the
signature. You must use the `-u` option to specify the key used to sign.

`-v` `--verify`

Verify the first file using the second file as signature. It will check the
signature present in the file given as second argument of the command line
against the file given as first argument in the command line. If the
signature is valid it will show the signer and any comments available.

`--armor`

With this option the signature file will be written or read in base 64 encoding. You
can use this encoding to send the signature as text.

`--clearsign`

Clearsign the file. The first file will be read as text and it will be copied 
to the second file together with a signature appended at the end. You must 
specify the signing key by using the `-u` option. If there is a third 
argument it will be interpreted as a comment that is part of the signature 
and is also checked by the signature.

`--clearverify`

Clearverify the input file. The file will be read and the embedded signature
will be verified.

`--clearresign`

Clearsign the file again. It assumes that the first argument is the name of a 
file that was already clear signed, but has been modified after being signed. 
This option signs the contents again and creates a valid clear signed file.
There may be a second optional argument which if given will be written as the 
comment in the signature.

`--add-certs`

Add certificates of the signing key to the signature. This will include in
the signature the name of the signer and any certificates that are in the
signing key. When verifying the signature the program will first check that
the signature is correct and will display the signing key. If the signing key
can be found in the key ring then also the name of the signing key will be
displayed. If the signing key cannot be found in the key ring then no name
will be displayed if no certificates were added. If certificates were added
then the name and creation date embedded in the signature will be shown as
the unverified name of the key. The certificates will be checked and for each
valid certificate the key and name (if known) of the certifier will be shown.

The typical use case is if we are signing with working keys that are replaced
periodically. We may get a document signed with an old, expired, working key
that we do not have in our key ring. We may however have the master key
corresponding to the working key in our key ring. In this case the program
will say that the document was signed by an unverified key with an alledged
name and creation date and certified by the certifiers. If the master key has
certified the working key then the user will see that this was a key
certified by the master key and may decide to trust it. It is up to the user
to decide if a signature with an old key is to be trusted or not. If the
document is an old document then we will accept the signature as having been
produced in the past. In other cases we may insist on having signatures
produced with current keys.

Note that if a past working key has been compromised then the attacker could
produce signatures for that key and there would be no way to verify that
these signatures were created in the past. The holder of the signing key can
write into the signature any date that he wishes. Although the signing date
is signed by the key and verified by the program, in case that the attacker
has the signing key there is no way to determine the actual date.

`--pack`

Pack all files into the output file. The files will be put together into a
compressed archive and the archive will be encrypted. Note that you must also
specify the `-c` or `-e` option to select the type of encryption that you
wish to apply to the archive. If neither `-c` nor `-e` are specified then the
archive will be created as plain text, without encryption. Creating a plain
text archive and then encrypting the archived file is the same as the direct
archiving with encryption.

`--pack-list`

This will consider the input file as a packed archive and it will list the
files that it contains. If the file was encrypted with a password you must
also pass the `--dc` option. If the file was encrypted with a padlock then
you must pass the `--de` option. If neither `--dc` nor `--de` are passed the
file is assumed to be a plaintext archive.

`--noz`

Do not compress the files in the archive.

`--unpack` *packed*

Unpack from the packed file *packed* the files named in the command line. If
a directory is named then all the files in that directory will be unpacked.
You must also pass the `--dc` option if the file was encrypted with a
password or the `--de` option if the file was encrypted with a padlock.

`--unpack-all` *packed*

Unpack all the files present in the packed archive *packed*. You must also
pass the `--dc` option if the file was encrypted with a password or the
`--de` option if the file was encrypted with a padlock.

`--spoof`

Public padlock encryption pretending that the recipient wrote the file to the
sender. The tool will create a file or packed archive that will look like the
key selected with the `-r` option wrote the file for the padlock selected
with the `-u` option. Note that you only need the public padlock of the `-r`
padlock but you need both the padlock and private key of the key selected
with the `-u` option. See the description about repudiation for the use of
this option.

`--hide`

Encrypt the two files given as arguments into a single output file. The
program will prompt for two passwords. The first password will be used to
encrypt the first file. The second password will be used to encrypt the
second file and hide it in the encrypted file. The file can be decrypted
using the normal commands using the first password and will reveal the first
file. You can then decrypt the second file using the `--reveal` option. The
second file is hidden in the padding bytes. If there is not enough space in
the padding bytes for the second file, then the program will complain. You
can ensure that there is enough space in the padding bytes by using explicit
`block-size` and `block-filler` options or better just use a big file
(picture or video) as the first file.

`--reveal`

Decrypt the file given in the first argument using two passwords. Store in
the output file the second encrypted file. You will be asked for two
passwords. The first one is the normal password that is used to decrypt the
first file. The second password is the one that was used to encrypt the
hidden file.

`--hidek` *padlock2*

Encrypt the two files given as arguments into a single file, like with the
`--hide` option. This is used with padlocks. You specify the sender with the
`-u` option and the recipients with the `-r` options. The first file will be
encrypted for the recipients as normal. The second file will be hidden in the
first file and will be encrypted with the padlock given as argument to the
`--hidek` option. The hidden text can be decrypted only by using the private
key corresponding to the padlock *padlock2*.

`--revealk` *key2*

Decrypt the file given as the first argument by using two keys. You specify
the normal key to be used to decrypt the normal encrypted text with the `-u`
option. In addition the hidden text will be decrypted by using the key *key2*.

`--wipe`

Wipe out the input file that has been encrypted by overwriting it with random
bytes.

`--block-size` *bytes*

Set the size of the output blocks in bytes when encrypting. All input and
output done with the encrypted file is done in chunks of block-size bytes.
The program normally selects this with a random value but you can specify
what you wish to have.

`--block-filler` *bytes*

Set the amount of filler bytes per block. Each block carries block filler
dummy bytes that alter the final size of the file. If block size if 4000 and
block filler is 1000 then 25% of the size of the encrypted file will be dummy
bytes and 75% will be payload bytes.

`--shifts` *val*

Set the shifts parameter for the processing of the password. The default
value is 14. When you increase this parameter by 1 then the memory and CPU
time required for processing the password doubles. With a default value of 14
the system requires 16 MB of memory. The higher the value the longer it takes
to process the password. It makes the work of password guessing programs more
difficult because each try takes more time. By default, the decryption
program will not allow a shifts value higher than 20. This value already
requires 1 GB of memory to run and higher values may result in extremely long
processing times on low end systems whenever you enter a wrong password. Note
that the best protection against password cracking is a long random password.
The additional processing done by the program is just a tool to mitigate the
lack of randomness of most passwords.

When decrypting this parameter sets the limit of the shifts parameter that we
will accept. This limits the damage that a too high value may create a denial
of service. You can set this parameter to any value. A high value will allow
you to match a corresponding high value set during encryption, but will also
increase the time that you must wait if you type a wrong password.

`--no-expand`

Do not expand the file. Same as block-filler=0.

`--inplace-enc`

Encrypt all the files given in the command line in place. The file will be 
overwritten while encrypting. No temporary files will be used. Only password 
based encryption is supported. This option is useful when encrypting big 
files on drives that do not have space for a temporary copy of the big file. 
The normal encryption would first encrypt to another file and then you could 
remove the original file. You would need free space in the drive to store the 
temporary file. With this option no temporaries are used. Note that the 
block-filler will be set to zero to minimize the expansion of the file.

`--inplace-dec`

Decrypt all the files given in the command line in place. The file will be 
overwritten while decrypting. No temporary files will be used. 

`--verbose`

Verbose output.

If you do not specify a key ring file then the environment variable
AMBER_KEY_RING will be read and if present it defines the name of the key
ring. If the variable is not set then the default is amber.keys.cha



Additional tools
================

There are some additional tools that may help to manage files.



wipe
----

The *wipe* utility will overwrite a file with random data. Keep in mind that
this tool is portable and there is no assurance that the actual media that
carries the file will be overwritten. It can be expected that a traditional
hard drive will reuse the same sectors. However solid state memories use wear
levelling algorithms that attempt to avoid rewriting the same sectors. This
utility has no means to enforce the actual writing of the physical media. You
can use *wipe* to overwrite a given file or to create a new file with random
bytes. The utility takes the names of the files to be generated or
overwritten from the command line. In addition it takes two options. If no
options are passed, the size of the overwritten file will be the same as the
size of the existing file.

 - The `-n` *size* option specifies the amount of bytes that will be
   written to the file: if a new file is created then it will have as many
   bytes. If the file already exists then it will be truncated to the
   given size.

 - The `-m` *size* gives the maximum size to be used for new files. If the
   `-n` option is not given but the `-m` option is passed, then when
   creating a new file a random value between 0 and the given size will be
   selected as the size of the new file. This option allows you to specify
   many files in the command line and they will get different sizes.


genpass
-------

The *genpass* utility generates a random password. This password is not case
sensitive and contains only ASCII characters. The output is divided into
groups of 4 characters. Each group carries 20 bits of entropy.



blakerng
--------

The *blakerng* utility can be used as a password wallet/generator. It will 
first ask for a master password. Then it will ask for identifiers. For each 
identifier it will generate a password and a numeric PIN based on the master 
password and the identifier. The intended use is that you memorize a long and 
random master password. Then for each service that you need you just write on 
a piece of paper an identifier. To recover the password for that service you 
supply the master password and the identifier. The identifier may be just the 
name of the service, or even better another random password used as secret 
identifier. In the latter case you are effectively using a two item 
authentication, because you need the master password (in your head) and the 
service specific secret identifier stored on paper. Both contribute to the 
security of the generated password. If somebody steals the paper with the
secret identifier then the thief cannot derive the password because he lacks 
the master password. 



Examples
========

To create the keys for Alice, Bob, Carol and Eve we use

	amber --gen-master "Alice Wonder <alice@wonderland.net>" --master:master-alice.cha
	amber --gen-master "Bob Builder <bob@builder.com>" --master:master-bob.cha
	amber --gen-master "Carol Doe <carol@foo.com>" --master:master-carol.cha
	amber --gen-master "Eve Evil <eve@nsa.gov>" --master:master-eve.cha

After this we can see the padlocks by using

	amber -k

We now create a work key for Alice using

	amber --gen-work --master:master-alice.cha

We now create work keys for Bob and Carol:

	amber --gen-work --master:master-bob.cha
	amber --gen-work --master:master-carol.cha

Whenever --gen-work is used it will look for a master key. If there is only
one (like in the examples, as it has been supplied by the --master option)
then that unique key will be used. If there are several then select the key
using the -u option.

If we want to see the certificates attached to the padlocks we use

	amber --list

This will show that by default each of the padlocks has a certificate by the
owner of the key. If a padlock and a key pair are available then the list
will show it as a private key. If only the padlock is available then it will
show it as padlock. In addition it will show if it is a master or a work key.
When showing the padlocks in compact form an M will be prepended if the
padlock is a master padlock and a W will be prepended if the padlock is a
work padlock.


If Alice wants to certify that Bob's padlocks really belong
to Bob she certifies it

	amber --certify-by Alice -p Bob --master:master-alice.cha

You need to have a master key in order to be able to certify other keys. The
option `--master` has supplied the file that contains the master key. The
`-p` option selects all keys which contain the word `Bob`.

We can check the additional certification with

	amber --list

If Alice and Bob are members of the group of conspirers we can add an alias
to them:

	amber --alias conspirer -p Alice -p Bob

We check it with the list command:

	amber --list

This will show that we gave the `conspirer` alias to both Alice and Bob. Now
carol can encrypt the file foo.txt for the conspirers:

	amber -e foo.txt -o foo.cha -u Carol -r conspirer

The command will show that Alice and Bob were selected as receivers. Now Bob
can decrypt the file foo.cha using

	amber --de foo.cha -o foo.dec -u Bob

If Bob wants to export his padlock to the file `bob.key` he can use

	amber --export bob.key -r Bob

He can check the exported contents:

	amber --list-file bob.key

The key ring file is required to provide a name for the cerfifier of the
padlock. If we didn't have Alice in our key ring we would be able to show the
raw value of the padlock that certified the padlock but we would not know the
name of the owner of the certifying padlock. Carol can import Bob's padlock
into her key ring by using

	amber --import bob.key

If Alice wants to encrypt the file foo.txt using a password she will use

	amber -c foo.txt -o foo.cha

The program will ask for the password twice to make sure it was not mistyped.
She can decrypt it by using

	amber --dc foo.cha -o foo.dec

She will have to give the same password as before. If Alice wants to send a group
of files to Carol she can use:

	amber -e --pack -u Alice -r Carol -o foo.pack *.txt

Carol can see which files are in the pack by using

	amber --pack-list --de -u Carol foo.pack

She can extract the files foo.txt and bar.txt by using

	amber --unpack foo.pack --de -u Carol foo.txt bar.txt

She can extract all the files by using

	amber --unpack-all --de -u Carol foo.pack

Alice can sign the document foo.txt and put the signature in foo.txt.sig

	amber -s -u Alice foo.txt foo.txt.sig --add-certs

This signature can be verfified by using

	amber -v foo.txt foo.txt.sig

Alice can also clear sign the file foo.txt by using

	amber --clearsign -u Alice foo.txt foo.signed --add-certs

The file foo.signed will contain the original text with the signature
appended to it. To verify this file you can use

	amber --clearverify foo.signed

Alice may edit the foo.signed file and change its contents. If she does not
update the signature then the signature verification will fail because it was
changed since it was signed. To sign it again she can use

	amber --clearresign -u Alice foo.signed

This will update the signature in the file. Bob can pretend that Alice sent
him the encrypted file foo.cha with contents foo.txt:

	amber --spoof -u Bob -r Alice foo.txt -o foo.cha

Then he can go to his boss and show him his own private key and decrypt the
message

	amber --de -u Bob foo.cha -o foo.dec

It will look like if Alice sent it. This allows Alice to deny having sent any
message because Bob is also able to spoof the message. However only Bob can
spoof a message addressed to him. Therefore the boss knows that the message
shown to him by Bob (by also disclosing Bob's private key in order to be able
to decrypt the message) could have been created only by either Alice or Bob,
but nobody else. When Bob receives such a message he knows whether he spoofed
it or not. If he didn't spoof it then he knows without doubt that it was
created with Alice's private key. Third parties don't know which one of Alice
or Bob wrote it even when given the decryption key.

If you want to use an encrypted key ring just name it with the `.cha`
extension. The program will treat key rings ending in `.cha` as encrypted key
rings. An encrypted key ring can also be produced by just using amber to
encrypt it with a password:

	amber -c foo.key -o foo.key.cha

If you want to hide the file *secret.txt* so that if you are forced to
decrypt it it will produce the file *innocent.txt* then use

	amber --hide -o foo.cha innocent.txt secret.txt

This will prompt for a password to use for the file *innocent.txt* and
another password to use for the file *secret.txt*. If Alice forces you to
decrypt it you can use

	amber --dc foo.cha -o foo.dec

and give the first password. It will decrypt to the contents of
*innocent.txt*. To recover the real file you use

	amber --reveal foo.cha -o foo.dec

It will prompt for two passwords and it will store in *foo.dec* the contents
of the original *secret.txt* file. Even if Alice knows the first password she
does not know if the encrypted file contains further information or not. The
same deniable encryption is available when using padlocks and keys. Alice
wants to send a hidden file to Bob. Bob has two padlocks, Bob1, which is his
well known public padlock and a second one, Bob2.

	amber --hidek Bob2 -u Alice -r Bob1 innocent.txt
		  secret.txt -o foo.cha

This will encrypt innocent.txt for Bob1 as usual. It will also hide
secret.txt within the encrypted file by using the padlock Bob2. Eve forces Bob
to decrypt the message. Bob does it by using the Bob1 key:

	amber --de -u Bob1 foo.cha -o-

Eve sees that the encrypted file decrypts to the contents of innocent.txt.
However, after Eve is gone, Bob can still decrypt the hidden text by using

	amber --revealk Bob2 -u Bob1 foo.cha -o-

This will show the contents of secret.txt.

Note that for hiding files in other files there must be enough space in the
padding bytes to contain the second file. The program will complain if there 
is not enough space for the second file. You can ensure that there is enough 
space in the padding bytes by either:

1. Using a big file, like pictures or video, for the first file. This will
   normally select an amount of padding that is about the same order as the
   file itself.

2. Use the `--block-size` and `--block-filler` options to specify the exact 
   size of each block and the amount of filler bytes within each block. Note 
   that by using this option you may give cues that there might be a second 
   file, if the block size and block filler size that you select are not
   plausible automatic choices of the program.


Ringless operation
------------------

The above examples show how to use *amber* in the normal way: storing your 
private key and the padlocks of your correspondents in the key ring. This is 
convenient. You can also export your key ring from one device and import it 
into another one. There is another mode of operation, which does not use a 
key ring. It is based on the idea of using a password to generate your own 
padlock and key. This was implemented in the pegwit and sks-ecc tools. It has
been lately promoted by minilock. Keep in mind that in this mode of operation
the whole security of the encrypted file depends on your password. If the
password is weak then an attacker can just guess the password.

You can pass the --ringless option to signal that your private key will be
computed from the password that you supply.

	amber --ringless -e --lockid 274eUZM7YAroLWii6VevgSSsMLcWiTM3mNbL2zzPrhJML2 foo.txt -o foo.cha

The command above will encrypt the file `foo.txt` into `foo.cha` for the
padlock `274eUZM7YAroLWii6VevgSSsMLcWiTM3mNbL2zzPrhJML2`. It will ask for a
password. The password will be used to derive the key and padlock of the
sender. The recipient of the file `foo.cha` can decrypt it using

	amber --ringless --de foo.cha -o-

The program will ask for the password of the recipient in order to derive the
private key of the recipient. If you want to use ringless encryption and want
to send your padlock to others then use the following command to view your
public padlock:

	amber --ringless

This will ask you for the password and will show the corresponding padlock.


