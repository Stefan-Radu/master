#include <stdio.h>
#include <stdlib.h>

typedef struct lnode {
    int val;
    struct lnode *nxt;
} lnode;

int is_prime(int k) {
    for (int d = 2; d * d < k; ++d) {
        if (k % d == 0) {
            return 0;
        }
    }
    return 1;
}

void add(lnode** node, int v) {
    lnode* new_node = (lnode*) malloc(sizeof(lnode));
    new_node->val = v;
    if (*node != NULL) {
        (*node)->nxt = new_node;
        *node = new_node;
    } else {
        *node = new_node;
    }
}

void print(lnode *node) {
    while (node != NULL) {
        printf("%d ", node->val);
        node = node->nxt;
    }
}

int main() {
    lnode* root = NULL;
    lnode* curr_node = root;

    for (int i = 0; i < 42; ++i) {
        if (is_prime(i)) {
            add(&curr_node, i);
            if (root == NULL) {
                root = curr_node;
            }
        }
    }

    print(root);
}
