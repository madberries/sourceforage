# Building ComfortFuzz Docker Image

1) Before building the docker image, first make sure that you have generated an
   ssh key pair (as described [here](https://docs.gitlab.com/ee/ssh/README.html#generate-an-ssh-key-pair]).
   The keys you generate should go here in this directory and the private/public
   keys should be saved as 'gitlab\_key'/'gitlab\_key.pub'.

2) Now you need to add the public key that was generated in the previous step
   to your list of ssh keys in your gitlab user settings.

3) Once you have done that, build the docker we are going to use to run the
   comfortfuzz exploit generation:

   ```
   docker build -t comfortfuzz .
   ```
