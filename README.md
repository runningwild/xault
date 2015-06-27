The name, Xault (it's like Vault, but with an 'X'!  That's cool, right?), is shitty.  Such a shitty name prevents me from keeping it because I'm too lazy to make a better one.  So just keep that in mind.

Basic idea is a sensible method of key-exchange that can be used to grow a user's web of trust, and in turn lets you use this to establish secure lines of communication and filesharing.

Dropbox doesn't seem to have a good track-record when it comes to security, and even though your data is encrypted in flight and on their servers, they hold the keys.  This is fine for most people, but for anyone that doesn't want a breach on Dropbox to mean a breach on their own data, this isn't good.

If you look at [The Eff Scorecard](https://www.eff.org/secure-messaging-scorecard) there are a few messaging apps that are considered very secure and do manage to encrypt all messages with keys that the server doesn't have, so they don't have the kind of problem that Dropbox does.  I don't know a lot about all of these, but most of the ones that are very secure aren't very user-friendly (cryptocat, obviously PGP), and even some that do check all the boxes are shunned by a lot of security experts (Telegram).  In any case, these are targeted at messaging in general, even though most do support arbitrary files.

The most interesting thing that I have right now is the key-exchange mechanism.  You and a contact click the 'Exchange Keys' button, tap your phones, and now you've got each other's public keys.  This avoids a problem that both Telegram and SecureText (arguably the best one out there in terms of both usability and security) have where to ensure a line of communication is completely secure you have to compare the value of a long hex string or a pixely image.  Also it is a way of handling security that should make sense to a normal user, and that doesn't require any kind of password.  Additionally you have a few choices with how you handle your contacts, you can allow them to share your contact information with their contacts, and you can share their contact information with other contacts of yours.  The details of this I need to work out, but it would allow you to grow your web of trust without exchanging keys in person.

Other small bonus features:
- The app can expose a Signature Intent that other apps could use to let the user sign any piece of data using their keys from this app.  Other users could verify this signature using a similar Verify Intent.
- The app could let you send/receive PGP signed emails.  I'm not totally sure how to make this work though, sending the emails would be easy, verifying them would be a little harder, unless we could convince the gmail app to include it (probably not).
- If necessary you can exchange keys remotely by sending a couple QR codes through email.
- I've already implemented an interesting backup mechanism.  When you first start up your app you generate a public/private key pair, and you also generate a phrase of about 15 words that you can write down to recover your key later.  