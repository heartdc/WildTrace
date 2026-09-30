struct frame {
    int len;
};

void consume(struct frame *fr) {
    fr->len = 1;
}

int main(void) { struct frame f = {0}; consume(&f); return 0; }
