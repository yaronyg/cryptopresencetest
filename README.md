# cryptopresencetest

This is a test. This is only a test.

The purpose of the repo is to explore how to securely perform discovery in BLE. I do have
a specific proposal available [here](http://www.thaliproject.org/presenceprotocolforopportunisticsynching).

The code in this project is broken into two parts. In main/java/org.thaliproject.cryptopresencetest.app/DiscoveryAnnouncement
is code that actually implements what is in the spec. This code is just meant to explore how
to implement the spec. It has not been properly tested for performance or (gulp) correctness.

Below is an example of generating a discovery announcement.

```Java
        byte[] discoveryAnnouncement = DiscoveryAnnouncement
                .generateDiscoveryAnnouncement(listOfReceivingDevicesPublicKeys,
                        kx, millisecondsUntilExpiry);
```

And here is an example of parsing a discovery announcement.

```Java
        byte[] foundIndex =
                DiscoveryAnnouncement
                        .parseDiscoveryAnnouncement(discoveryAnnouncement, kyAddressBook, ky);
```

If foundIndex is null then the announcement wasn't for the local machine. If foundIndex is
not null then that will give the sha256 hash of the X.509 encoded public key of the device
that is trying to contact us.

These examples, btw, are taken from our end to end test in 
DiscoveryAnnouncementTest.java/testGenerateDiscoveryAnnouncement.

There is another section of tests under performanceHack. These tests were just sketches I
created of alternative proposals and explorations I made of various types of crypto functionality.
I used these tests to do very crude performance measurements.