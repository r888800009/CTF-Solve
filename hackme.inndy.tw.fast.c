#include <stdio.h>
int main() {
  int a, b;
  char op;
  int count = 0;
  while (scanf("%d %c %d", &a, &op, &b) != EOF && count < 10000) {
    if (op == '+') printf("%d\n", a + b);
    if (op == '-') printf("%d\n", a - b);
    if (op == '*') printf("%d\n", a * b);
    if (op == '/') printf("%d\n", a / b);
    count++;
    fflush(stdout);
  }

  return 0;
}
