from stix2 import Artifact



artifact = Artifact(url='https://example.com', hashes={'MD5':'0cc175b9c0f1b6a831c399e269772661'}, object_marking_refs=['marking-definition--4c66b18d-e560-46e2-8bb1-d43d10617fc7'])

print(artifact.serialize(pretty=True))

