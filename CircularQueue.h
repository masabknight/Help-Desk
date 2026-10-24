// Array-based circular queue (FIFO) for pending help desk requests.
// enqueue / dequeue / peek / isEmpty / isFull are all O(1); display is O(count).
#pragma once
#include <string>
#include <vector>

struct QueueItem {
    int requestId = 0;
    int userId = 0;
    std::string regNo, category, description, createdAt;
};

class CircularQueue {
public:
    explicit CircularQueue(int capacity)
        : capacity_(capacity > 0 ? capacity : 1), front_(0), rear_(capacity_ - 1),
          count_(0), data_(capacity_) {}

    bool isEmpty() const { return count_ == 0; }
    bool isFull() const { return count_ == capacity_; }
    int size() const { return count_; }
    int capacity() const { return capacity_; }
    int front() const { return front_; }
    int rear() const { return rear_; }

    // Insert at rear. Never overwrites: returns false if full.
    bool enqueue(const QueueItem& item) {
        if (isFull()) return false;
        rear_ = (rear_ + 1) % capacity_;          // circular indexing
        data_[rear_] = item;
        ++count_;
        return true;
    }
    // Remove from front. Returns false if empty.
    bool dequeue(QueueItem& out) {
        if (isEmpty()) return false;
        out = data_[front_];
        front_ = (front_ + 1) % capacity_;
        --count_;
        return true;
    }
    bool peek(QueueItem& out) const {
        if (isEmpty()) return false;
        out = data_[front_];
        return true;
    }
    // Physical array index of the i-th logical element (0 = front).
    int physicalIndex(int i) const { return (front_ + i) % capacity_; }

    // Logical FIFO order: start at front, move circularly for exactly count elements.
    std::vector<QueueItem> display() const {
        std::vector<QueueItem> v;
        for (int i = 0; i < count_; ++i) v.push_back(data_[physicalIndex(i)]);
        return v;
    }

private:
    int capacity_, front_, rear_, count_;
    std::vector<QueueItem> data_;   // fixed size, never resized
};
