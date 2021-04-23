test:
	python3 fileget.py -n 127.0.0.1:5050 -f fsp://moj.server/firstfile -d

testall:
	python3 fileget.py -n 127.0.0.1:5050 -f fsp://moj.server/* -d

zip:
	zip xrepka07-src.zip *.py

clean:
	-rm test firstfile secondfile index *.zip
