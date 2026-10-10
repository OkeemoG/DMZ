.PHONY: images deploy destroy test2 test

images:
	bash images/build.sh

deploy: images
	containerlab deploy -t topology/dmz.clab.yml --reconfigure

destroy:
	containerlab destroy -t topology/dmz.clab.yml --cleanup

test2:
	bash topology/test/test2.sh

test:
	containerlab deploy -t topology/test/basicTest.clab.yml
	docker exec clab-basicTest-a ping -c 2 10.0.0.2
	containerlab destroy -t topology/test/basicTest.clab.yml --cleanup