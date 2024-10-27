#include <iostream>


class Vehicle {
public:
    virtual void move() = 0;
};

class Aircraft: public Vehicle {
public:
    virtual void move() override {
        std::cout << "moving aircraft" << std::endl;
    }

    void fly() {
        std::cout << "Flying!!" << std::endl;
    }
};

class Car: public Vehicle {
public:
    virtual void move() override {
        std::cout << "moving car" << std::endl;
    }

    void drive() {
        std::cout << "Driving!!" << std::endl;
    }
};

class Boat: public Vehicle {
public:
    virtual void move() override {
        std::cout << "moving boat" << std::endl;
    }

    void swim() {
        std::cout << "Swimming!!" << std::endl;
    }
};

class FlyingCar: public Aircraft, public Car {
public:
    virtual void move() override {
        std::cout << "moving flying car" << std::endl;
    }

    void switchMode(int m) {
        switch (m) {
        case 0:
            this->on_ground = true;
            std::cout << "now on ground!" << std::endl;
            break;
        case 1:
            this->on_ground = false;
            std::cout << "now in the air!" << std::endl;
            break;
        default:
            std::cout << "wrong type!!!" << std::endl;
        }
    }

private:
    bool on_ground = true;
};

class Amphibian: public Car, public Boat {
public:
    virtual void move() override {
        std::cout << "moving amphibian" << std::endl;
    }

    void switchMode(int m) {
        switch (m) {
        case 0:
            this->on_land = true;
            std::cout << "now on land!" << std::endl;
            break;
        case 1:
            this->on_land = false;
            std::cout << "now in water!" << std::endl;
            break;
        default:
            std::cout << "wrong type!!!" << std::endl;
        }
    }

private:
    bool on_land = true;
};
