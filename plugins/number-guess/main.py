#!/usr/bin/env python3
import json
import random
import sys
TEXT={"zh-CN":{"new":"我选了 1 到 20 之间的一个数字，你有 6 次机会。","guess":"你的猜测（q 退出）：","integer":"请输入 1 到 20 的整数。","range":"数字必须在 1 到 20 之间。","again":"再试一次：","win":"猜中了！答案是 {secret}，共用了 {tries} 次。","lost":"机会用完了，答案是 {secret}。","high":"大了","low":"小了","left":"{guess} {direction}，还剩 {left} 次。","continue":"继续猜："},"en":{"new":"I picked a number from 1 to 20. You have 6 tries.","guess":"Your guess (q to quit): ","integer":"Enter an integer from 1 to 20.","range":"The number must be from 1 to 20.","again":"Try again: ","win":"Correct! The answer was {secret}; you used {tries} tries.","lost":"No tries left. The answer was {secret}.","high":"is too high","low":"is too low","left":"{guess} {direction}; {left} tries remain.","continue":"Keep guessing: "}}


def main(request):
    locale="zh-CN" if str(request.get("locale","en")).lower().startswith("zh") else "en";text=TEXT[locale]
    action = request.get("action")
    state = request.get("state", {})
    if action == "new":
        return {
            "message": text["new"], "prompt": text["guess"], "locale": locale,
            "state": {"secret": random.SystemRandom().randint(1, 20), "tries": 0},
            "done": False,
        }
    try:
        guess = int(state.get("input", ""))
        secret = int(state["secret"])
        tries = int(state.get("tries", 0)) + 1
    except (TypeError, ValueError, KeyError):
        return {"message": text["integer"], "prompt": text["again"], "state": state, "done": False, "locale": locale}
    if not 1 <= guess <= 20:
        return {"message": text["range"], "prompt": text["again"], "state": state, "done": False, "locale": locale}
    if guess == secret:
        return {"message": text["win"].format(secret=secret,tries=tries), "state": {}, "done": True, "locale": locale}
    if tries >= 6:
        return {"message": text["lost"].format(secret=secret), "state": {}, "done": True, "locale": locale}
    direction = text["high"] if guess > secret else text["low"]
    return {
        "message": text["left"].format(guess=guess,direction=direction,left=6-tries), "prompt": text["continue"], "locale": locale,
        "state": {"secret": secret, "tries": tries},
        "done": False,
    }


request = json.loads(sys.stdin.buffer.readline(65_537))
print(json.dumps(main(request), ensure_ascii=False))
