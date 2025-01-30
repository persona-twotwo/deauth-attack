# 컴파일러와 컴파일 옵션 설정
CXX = g++
CXXFLAGS = -lpcap

# 타겟과 소스 파일 설정
TARGET = deauth-attack
SRC = deauth-attack.cpp

# 기본 타겟
all: $(TARGET)

# 타겟 빌드 규칙
$(TARGET): $(SRC)
	$(CXX) $(SRC) -o $(TARGET) $(CXXFLAGS)

# 클린업 규칙
clean:
	rm -f $(TARGET)
