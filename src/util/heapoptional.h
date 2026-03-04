// Copyright (c) 2022-2024 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_UTIL_HEAPOPTIONAL_H
#define BITCOINII_UTIL_HEAPOPTIONAL_H

#include <functional>
#include <memory>
#include <utility>

/**
 * An optional that stores its value on the heap, rather than in-line,
 * in order to save memory. Implemented using std::unique_ptr.
 *
 * This optional is a drop-in replacement for std::optional but with
 * the in-line cost of a unique_ptr. Like an optional but unlike a
 * unique_ptr, it can be treated as a value type (copy-constructible
 * and copy-assignable via deep copy).
 *
 * Used for CashTokens token data in CTxOut, which is null in most cases.
 */
template <typename T>
class HeapOptional {
    std::unique_ptr<T> p{};
public:
    using element_type = T;

    constexpr HeapOptional() noexcept = default;
    explicit HeapOptional(const T& t) { *this = t; }
    explicit HeapOptional(T&& t) noexcept { *this = std::move(t); }

    template <typename ...Args>
    explicit HeapOptional(Args&& ...args) { emplace(std::forward<Args>(args)...); }

    HeapOptional(const HeapOptional& o) { *this = o; }
    HeapOptional(HeapOptional&& o) = default;

    template <typename ...Args>
    void emplace(Args&& ...args) { p = std::make_unique<T>(std::forward<Args>(args)...); }

    HeapOptional& operator=(const HeapOptional& o) {
        if (o.p) p = std::make_unique<T>(*o.p);
        else p.reset();
        return *this;
    }
    HeapOptional& operator=(HeapOptional&& o) noexcept = default;

    HeapOptional& operator=(const T& t) { p = std::make_unique<T>(t); return *this; }
    HeapOptional& operator=(T&& t) { p = std::make_unique<T>(std::move(t)); return *this; }

    operator bool() const { return static_cast<bool>(p); }
    T& operator*() { return *p; }
    const T& operator*() const { return *p; }
    T* get() { return p.get(); }
    const T* get() const { return p.get(); }
    T* operator->() { return p.operator->(); }
    const T* operator->() const { return p.operator->(); }

    void reset(T* t = nullptr) { p.reset(t); }
    T* release() { return p.release(); }

    bool operator==(const HeapOptional& o) const {
        if (p && o.p) return *p == *o.p;
        return !p && !o.p;
    }
    bool operator!=(const HeapOptional& o) const { return !(*this == o); }

    bool operator<(const HeapOptional& o) const {
        if (!p) return static_cast<bool>(o.p);
        if (!o.p) return false;
        return *p < *o.p;
    }
};

#endif // BITCOINII_UTIL_HEAPOPTIONAL_H
