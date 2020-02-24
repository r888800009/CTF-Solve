#include <cstdbool>
#include <fstream>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>

#define WORDLIST_SIZE 65

using namespace std;

const string wordlist =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_";

typedef struct Node {
  bool leaf;
  string next[WORDLIST_SIZE];
} Node;

map<string, Node> addressMapping;

string rootAddress = "";

void load() {
  fstream fin;
  string drop, commandLine, addressLine, dataLine, leaf;
  fin.open("dumpdata", ios::in);
  if (!fin) cout << "open error" << endl;

  // drop first line
  getline(fin, drop);

  getline(fin, commandLine);
  while (commandLine != "Dump end") {
    if (commandLine == "===== node =====") {
      // load node to data
      Node node;
      // address: 0x5569e30fb120
      getline(fin, addressLine);
      addressLine =
          addressLine.substr(addressLine.find(' ') + 1, addressLine.size());

      // leaf or root
      getline(fin, leaf);
      if (leaf == "1")
        node.leaf = true;
      else
        node.leaf = false;

      // node data
      getline(fin, dataLine);
      stringstream ss;
      ss << dataLine;

      for (int i = 0; i < WORDLIST_SIZE; i++) {
        string childAddress;
        ss >> childAddress;
        node.next[i] = childAddress;
      }

      // add struct to mapping
      addressMapping[addressLine] = node;

      // check first node and set root
      if (rootAddress == "") rootAddress = addressLine;
    }

    getline(fin, commandLine);
  }
}

string outputString;
// DFS
void traverse(const string &address) {
  Node node = addressMapping[address];
  if (node.leaf) {
    cout << outputString << endl;
    return;
  }

  for (int i = 0; i < WORDLIST_SIZE; i++) {
    if (node.next[i] != "0") {
      outputString.push_back(wordlist[i]);
      traverse(node.next[i]);
      outputString.pop_back();
    }
  }
}

int main() {
  load();
  traverse(rootAddress);
  return 0;
}
