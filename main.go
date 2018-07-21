package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/Eric-GreenComb/keystore/ethereum"
)

var (
	keystore = `...`
)

func gen(charset string, n int, sc chan string) {

	for _, c := range charset {
		if n == 1 {
			sc <- string(c)
		} else {
			var ssc = make(chan string)
			go gen(charset[:], n-1, ssc)
			for k := range ssc {
				sc <- fmt.Sprintf("%v%v", string(c), k)
			}
		}
	}
	close(sc)
}

// GetFileLineNumber GetFileLineNumber
func GetFileLineNumber(name string) int {
	fi, err := os.Open(name)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return 0
	}
	defer fi.Close()

	_lineNum := 0
	br := bufio.NewReader(fi)
	for {
		_, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		_lineNum++
	}
	return _lineNum
}

// ReadLimitLine ReadLimitLine
func ReadLimitLine(name string, startLineNumber, limitNumber int, k *ethereum.EncryptedKeyJSONV3, sc chan string) {
	file, _ := os.Open(name)
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	lineCount := 0
	_limit := 0
	for fileScanner.Scan() {
		if lineCount >= startLineNumber {
			_passphrase := fileScanner.Text()
			_, err := ethereum.Ks.DecryptKeyV3(k, _passphrase)
			if err == nil {
				sc <- fmt.Sprintf(">>>>>>>>>>> right : %s", _passphrase)

				fs, e := os.OpenFile("pwd.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
				if e != nil {
					panic(e)
				}
				fs.WriteString(_passphrase)
				fs.WriteString(string("\n"))
				defer fs.Close()

				break
			} else {
				sc <- fmt.Sprintf("%s", _passphrase)
			}
			_limit++
		}
		if _limit == limitNumber {
			break
		}
		lineCount++
	}
	close(sc)
}

func main() {
	// _passphrase := "a11111"
	_bytes := []byte(keystore)

	_startTime := time.Now()
	runtime.GOMAXPROCS(runtime.NumCPU())

	_fileName := "./dictionary/6n.txt"

	_fileLine := GetFileLineNumber(_fileName)
	_limit := _fileLine / 4
	fmt.Println("file line number : ", _fileLine)
	fmt.Println("limit : ", _limit)

	k := new(ethereum.EncryptedKeyJSONV3)
	if err := json.Unmarshal(_bytes, k); err != nil {
		return
	}

	// _, err := ethereum.Ks.DecryptKeyV3(k, _passphrase)
	// if err != nil {
	// 	fmt.Println("error : ", err.Error())
	// } else {
	// 	fmt.Println("pwd : ", _passphrase)
	// }

	sc1 := make(chan string)

	_startNum := 0
	go ReadLimitLine(_fileName, _startNum, _limit, k, sc1)

	_startNum += _limit
	go ReadLimitLine(_fileName, _startNum, _limit, k, sc1)

	_startNum += _limit
	go ReadLimitLine(_fileName, _startNum, _limit, k, sc1)

	_startNum += _limit
	go ReadLimitLine(_fileName, _startNum, _limit, k, sc1)

	for x := range sc1 {
		fmt.Println(x)
	}

	_elapsed := time.Since(_startTime)
	fmt.Println("完成消耗时间:", _elapsed)

}
