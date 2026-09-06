#!/usr/bin/env python3
import json
import sys


MAZE = (
    "#######",
    "#S#   #",
    "# # # #",
    "#   #E#",
    "#######",
)
DIRECTIONS = {"w": (-1, 0), "s": (1, 0), "a": (0, -1), "d": (0, 1)}
TEXT={"zh-CN":{"new":"走到 E：w/a/s/d 分别控制上/左/下/右。","invalid":"游戏状态无效。","keys":"只接受 w、a、s、d。","wall":"撞墙了。","go":"继续前进。","win":"到达出口！共走了 {moves} 步。","prompt":"方向："},"en":{"new":"Reach E: w/a/s/d move up/left/down/right.","invalid":"Invalid game state.","keys":"Use only w, a, s, or d.","wall":"You hit a wall.","go":"Keep going.","win":"Exit reached in {moves} moves!","prompt":"Direction: "}}


def render(row, column):
    lines = [list(line) for line in MAZE]
    lines[row][column] = "@"
    return "\n".join("".join(line) for line in lines)


def main(request):
    locale = "zh-CN" if str(request.get("locale", "en")).lower().startswith("zh") else "en"; text=TEXT[locale]
    state = request.get("state", {})
    if request.get("action") == "new":
        row, column, moves = 1, 1, 0
        message = text["new"]
    else:
        try:
            row, column, moves = int(state["row"]), int(state["column"]), int(state["moves"])
        except (KeyError, TypeError, ValueError):
            return {"message": text["invalid"], "state": {}, "done": True, "locale": locale}
        direction = DIRECTIONS.get(str(state.get("input", "")).lower())
        if direction is None:
            message = text["keys"]
        else:
            next_row, next_column = row + direction[0], column + direction[1]
            if MAZE[next_row][next_column] != "#":
                row, column = next_row, next_column
                moves += 1
            message = text["wall"] if (next_row, next_column) != (row, column) else text["go"]
    done = MAZE[row][column] == "E"
    if done:
        message = text["win"].format(moves=moves)
    return {
        "message": f"{message}\n{render(row, column)}",
        "prompt": text["prompt"], "locale": locale,
        "state": {"row": row, "column": column, "moves": moves},
        "done": done,
    }


request = json.loads(sys.stdin.buffer.readline(65_537))
print(json.dumps(main(request), ensure_ascii=False))
