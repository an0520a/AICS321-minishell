AICS321-minishell
===================

기본 요구 사항
-------------

  1. shell 변수 기능 구현 : “sname=kevin; echo $sname” 입력 시 kevin 출력 (shell 변수)
  2. export/unset 기능 구현 (세션 단위 환경변수 추가/제거) 
  3. echo 기능 구현 : shell 변수 및 환경변수 출력 기능 포함하고, 옵션은 고려하지 않음 : “echo hello” 입력 시 hello 출력 : “echo syspro > test.txt” 시 test.txt에 syspro 저장
  4. pipe (“|”) 명령어 구현 5. redirection 명령어 구현 : “<” → file의 내용을 stdout으로 출력 : “>” → stdout을 file에 저장 : “>>” → stdout을 file에 추가
  6. background (“&”) 명령어 구현
  7. multiple 명령어 구현 : “;” → 명령어 성공 여부와 상관없이 순차적으로 명령어 실행 : “&&” → 명령어 성공 시 다음 명령어 실행 : “||” → 명령어 실패 시 다음 명령어 실행
  8. change directory (“cd”) 명령어 구현 
  9. history 명령어 구현 
  10. asterisk (“*”) 처리 
  11. stop (“ctrl + c”) 명령어 구현
  12. shell name 변경 (user_name@pwd 추가) → e.g., “kevin@/usr/bin$“
  
 보너스 요구사항
 --------------
  1. left/right cursor 기능 구현 
  2. top/down cursor 기능 구현 (command history) 
  3. tab cursor (자동완성) 
  4. “ctrl + r” 기능 구현 (upgrade history)
  
채점 기준
-------
- 기본 요구사항 10개 이상 구현 
- 보너스 요구사항을 구현하는 경우 최대 20점까지 가산점
- 다양한 예외 case에 대한 robustness (error 발생 시 감점)

구현 결과
--------
기본 요구 사항 중, pipe를 제외한 전부를 구현함
