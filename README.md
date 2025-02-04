# [Deauth Attack](https://gitlab.com/gilgil/sns/-/wikis/deauth-attack/report-deauth-attack)

## 과제
Deauth Attack 프로그램을 작성하라.

## 실행
- ap channel과 wlan 장치의 channel을 일치시킨 후 작동시켜야 합니다.
```
syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]
sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
```
- 실행 영상: [broadCast](https://youtu.be/HWsY1NP47ts), [uniCast](https://youtu.be/IOnSOWyCi-4)

## 후기
- 제가 사용한 공유기에서 auth attack이 작동하지 않았습니다. auth attack을 시도할 경우 연결이 끊기는게 아닌 네트워크가 먹통이 됩니다. sleep을 주어 부하를 줄였음에도 해결되지 않아 auth 부분은 코드를 제출하지 않고 deauth 부분만 제출합니다.
- channel을 자동으로 맞춰주려 하다가 생각보다 프로그램 규모가 커지는것 같아 채널부분은 제외하였습니다.
