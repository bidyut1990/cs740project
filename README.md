# cs740project
Multi-tenant policy-aware congestion control algorithms for P4 switches

This work presents the study of this paradigm and describes the implementation details of a control strategy to effectively allocate fair bandwidth among multiple tenants, a common use case in data centre traffic, and thus achieve fair congestion control. In this work, we would be choosing  a simple average weighted policy to fairly divide the congestion among multiple tenants and find that an easily realizable feedback loop, by parsing custom information in the packets, is able to control congestion within a few RTT's.  
