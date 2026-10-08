test:
	containerlab deploy -t topology/test/basicTest.clab.yml
	docker exec clab-basicTest-a ping -c 2 10.0.0.2
	containerlab destroy -t topology/test/basicTest.clab.yml --cleanup
