.PHONY: images deploy destroy test-basic test-images test-topology

images:
	bash scripts/build-images.sh

deploy: images
	containerlab deploy -t topology/dmz.clab.yml --reconfigure

destroy:
	containerlab destroy -t topology/dmz.clab.yml --cleanup

test-images:
	bash tests/test-images.sh

test-topology:
	bash tests/test-topology.sh

test-basic:
	containerlab deploy -t topology/basicTest.clab.yml
	docker exec clab-basicTest-a ping -c 2 10.0.0.2
	containerlab destroy -t topology/basicTest.clab.yml --cleanup