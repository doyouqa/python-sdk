# Need this to happen non-locally: in the cloud, in docker?
git clone https://github.com/OneID/developer-neustar-iot.git
cd developer-neustar-iot
git submodule update --remote oneid-connect-python #update
git add .
git commit -m "Pulls in Python API documentation"
git push
