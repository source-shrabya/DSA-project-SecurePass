#ifndef HASHNODE_H
#define HASHNODE_H

#include "Credential.h"

// HashNode represents a node in the linked list bucket.
// It holds the data (Credential) and a pointer to the next node.
class HashNode {
public:
    Credential credential;
    HashNode* next;

    HashNode(Credential cred) : credential(cred), next(nullptr) {}
};

#endif