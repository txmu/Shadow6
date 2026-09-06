#!/usr/bin/env python3
import json
import random
import sys


MOVES = {"石头": 0, "剪刀": 1, "布": 2, "rock": 0, "scissors": 1, "paper": 2}
NAMES = ("石头", "剪刀", "布")
TEXT={"zh-CN":{"new":"来一局石头剪刀布。","prompt":"石头/剪刀/布：","invalid":"请输入石头、剪刀或布。","again":"再选一次：","names":("石头","剪刀","布"),"draw":"平局","win":"你赢了","lose":"电脑赢了","result":"你出{player}，电脑出{computer}：{result}。"},"en":{"new":"Let's play rock paper scissors.","prompt":"Rock/paper/scissors: ","invalid":"Enter rock, paper, or scissors.","again":"Choose again: ","names":("rock","scissors","paper"),"draw":"draw","win":"you win","lose":"computer wins","result":"You chose {player}; computer chose {computer}: {result}."}}


def main(request):
    locale="zh-CN" if str(request.get("locale","en")).lower().startswith("zh") else "en";text=TEXT[locale]
    if request.get("action") == "new":
        return {"message": text["new"], "prompt": text["prompt"], "state": {}, "done": False, "locale": locale}
    value = str(request.get("state", {}).get("input", "")).strip().lower()
    if value not in MOVES:
        return {"message": text["invalid"], "prompt": text["again"], "state": {}, "done": False, "locale": locale}
    player = MOVES[value]
    computer = random.SystemRandom().randrange(3)
    if player == computer:
        result = text["draw"]
    elif (player - computer) % 3 == 2:
        result = text["win"]
    else:
        result = text["lose"]
    return {"message": text["result"].format(player=text["names"][player],computer=text["names"][computer],result=result), "state": {}, "done": True, "locale": locale}


request = json.loads(sys.stdin.buffer.readline(65_537))
print(json.dumps(main(request), ensure_ascii=False))
