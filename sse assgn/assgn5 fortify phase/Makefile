main:
	gcc main.c -static -o safe_main -lpthread
	python3 crypt.py 0xFF
	strip --strip-all safe_main
all:
	python3 crypt_bomb.py > crypt_bomb.h
	python3 compute_gf_bomb_generator.py > compute_gf_bomb.h
	python3 transfer_bomb.py > transfer_bomb.h
	python3 egg_calculator_bomb.py > egg_calculator_bomb.h
	gcc main.c -static -o safe_main -lpthread
	python3 crypt.py 0xFF
	strip --strip-all safe_main
main3:
	python3 crypt_bomb.py > crypt_bomb.h
	python3 compute_gf_bomb_generator.py > compute_gf_bomb.h
	python3 transfer_bomb.py > transfer_bomb.h
	gcc main3.c -static -o safe_main
	python3 crypt.py 0xFF
compile:
	gcc main.c -static
	python3 crypt.py 0xFF