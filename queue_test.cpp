#include "CircularQueue.h"
#include <cassert>
#include <iostream>

static QueueItem mk(int id) { QueueItem q; q.requestId = id; return q; }

int main() {
    CircularQueue q(5);
    QueueItem x;
    assert(q.isEmpty() && !q.dequeue(x));            // process empty queue
    for (int i = 1; i <= 5; i++) assert(q.enqueue(mk(i)));
    assert(q.isFull());
    assert(!q.enqueue(mk(6)));                       // 6th rejected
    assert(q.display().front().requestId == 1);     // nothing overwritten
    assert(q.dequeue(x) && x.requestId == 1);        // FIFO
    assert(q.dequeue(x) && x.requestId == 2);
    assert(q.enqueue(mk(6)) && q.enqueue(mk(7)));    // freed slots reused (wraparound)
    assert(q.rear() == 1 && q.front() == 2);
    auto v = q.display();
    int expect[] = {3, 4, 5, 6, 7};
    assert(v.size() == 5);
    for (int i = 0; i < 5; i++) assert(v[i].requestId == expect[i]);  // logical FIFO order
    std::cout << "All circular queue tests passed\n";
}
