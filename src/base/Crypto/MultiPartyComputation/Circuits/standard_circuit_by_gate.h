//
// Copyright (C) 2021 Stealth Software Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Description:
//   Data structure and functions for evaluation of 'standard' (2-in-N-out) circuits.
//
// Discussion Points: There is much discussion, which is organized as follows:
//   0) High-Level Design
//   1) Overview of the Design
//   2) Ordering (Indexing) of Global Inputs and Gates
//   3) Circuit File Format
//   4) Motivating how Circuit Info (gate op, wiring, values) is stored
//   5) Motivating the Format of the Circuit File
//   6) Concurrency
//
// Without further ado...
//   0) Regarding High-Level Design:
//      There are currently two approaches to circuit evaluation:
//      A) Per-Level Evaluation ('Breadth-First', or 'Flat'):
//         The circuit is grouped into distinct *levels* with gates put into the
//         lowest-depth level possible. Implications:
//           - Evaluation is done level-by-level. So there is a single back-and-
//             forth communication for every level: Client sends Server masked
//             values for all gates on the level, Server evaluates all gates,
//             and returns all obfuscated truth tables.
//           - Number of 'rounds' of communication is minimized (number of levels),
//             and each individual communication is large. Thus, good for scenarios
//             where the cost of reestablishing connection/hand-shake is high, but
//             bad for high-latency scenarios, where parties are dormant while
//             waiting for each (large) communication.
//      B) Per-Gate Evaluation ('Depth-First', or 'Deep'):
//         The circuit is viewed as a single chain, with all gates having a linear
//         indexing (gate0, gate1, ...). When a gate is to be evaluated, it is
//         guaranteed that the inputs are available (either from a lower-index
//         gate evaluation, or as global inputs from one of the parties). Implications:
//           - Evaluation is done gate-by-gate. Queues (FIFO) are maintained
//             and processed as soon as they are ready.
//           - Number of 'rounds' of communication is maximized (number of gates).
//             Thus, bad for scenarios where cost of reestablish connection is
//             high; but may be good for high-latency scenarios, where work
//             can be done simultaneously while waiting for communication transfer.
//      This file implements (B), standard_circuit.h implements (A).
//
//   1) Overview of the Design.
//      The design is made more complicated by the desire to maximize efficiency
//      by utilizing separate threads to parallelize where possible (reading
//      circuit file, reading each party's inputs, evaluating gates). In
//      particular, we will respect the practice that each data structure
//      (queue) will have at most one 'push' thread and one 'pop' thread.
//      A) Data Structures.
//         The following data structures will be used:
//           i) (Queue) Gates.
//               Holds Gate Operation and output wire *mappings*.
//               NOTE: The input wire (values) are *not* stored here (see below),
//               this is to stick true to the concurrency strategy of guaranteeing
//               a single 'push' (and, perhaps separate, single 'pop') thread per
//               data structure: The thread reading the circuit file will populate
//               gate op and output wiring info, while the thread reading the
//               inputs and/or the thread doing gate evaluation will be populating
//               the input wire values.
//          ii) (Queue) Values (x2).
//               Holds values (from global inputs and evaluated gates). There will
//               be two such structures: one for left inputs, one for right inputs.
//               NOTE: We use two structures instead of one (e.g. a pair<GV, GV>)
//               mainly due to concurrency: this guarantees there is at most *one*
//               ('pushing') thread that is accessing a memory location at a time).
//         iii) (map<UINT64, GenericValue) Extra Values.
//               Holds values (global input or evaluated gates) that map to a
//               gate not present in the above 'Gates' queue (see discussion below).
//         Note that the Gates and Values queues should be in 1-1 correspondence, so
//         that the head value(s) are the proper inputs for the head gate.
//         Note that for the 2-party case, there will be additional data structures
//         (for OT bits, Send/Receive queues, etc.).
//      B) Concurrency.
//         In the case of multiple CPU cores, the following separate processes
//         will happen in parallel:
//             i) Read circuit file
//            ii) Parse global inputs
//           iii) Evaluate gates in 'Gates'
//         Notice that all the above can be done in parallel, with each thread
//         hanging when it is done or when it is blocked (e.g. the corresponding
//         queue it is processing is empty). In particular, these 3 threads will
//         have instructions as follows:
//           - Read Circuit File Thread.
//             Starts at beginning of executable, hangs if ever gates_ has size
//             max_gates_in_queue_; will restart when gates_ size drops back down to
//             less than max_gates_in_queue_.  Terminates when the full file is read.
//             Values read will be used to populate:
//               - inputs_, [left | right]_constant_input_:
//                 For the inputs from each Party and Constant inputs
//               - gates_: For the GATES block
//             NOTE: This will require smart reading of the input file, i.e.
//             ifstream and ios:bin and ios:seekg so that we don't read the entire
//             file into memory.
//           - Parse Global Inputs Thread.
//             Reads global inputs file, and uses the mappings in inputs_ to fill
//             '[left | right]_values[_overflow]_, as necessary (see (c) below).
//           - Evaluate Gates Thread.
//             Starts only after all global inputs are read (since the values_
//             queue, which will need to be written to after evaluating the gate,
//             is locked until the thread parsing global inputs has completed).
//             Thread runs continuously, evaluating the current (head) gate in gates_.
//             Hangs when gates_ is empty and restarts when something gets added.
//         The above assumes we have at least 3 threads to run in parallel.
//         Below, we describe how design proceeds with fewer (or more) threads;
//         let 'X' denote thread_num_tasks_until_context_switch_.
//           - 1 thread.
//             Read CircuitFile Metadata (num gates, input mappings).
//             Then Cycle through (i), (ii), and (iii) as follows:
//               a) Do (i) until X gates have been read
//               b) Do (ii) until 2 * X inputs
//                  have been read (the extra factor of 2 is to ensure we have enough
//                  inputs for X gates, since each gate has two wires)
//               c) Do (iii) until X have been processed.
//               d) Repeat steps (a) - (c) until done.
//             Note that the reason we alternate between tasks (i) - (iii), as opposed
//             to e.g. just doing (i) then (ii) then (iii), is because for extremely
//             large circuits (when number of gates exceeds max_gates_in_queue_),
//             switching between tasks (i) - (iii) may allow for successful evaluation,
//             whereas we'd fail if we tried to load all gates (or inputs) into memory.
//           - 2 threads.
//             Thread 1 reads circuit file.
//             Thread 2 cycles between (ii) and (iii), reading 2 * X (global) inputs
//             at a time and then evaluating X gates.
//           - 3 threads.
//             Assign each thread a task (i) - (iii). Once any thread finishes, it
//             simply dies (as opposed to helping one of the remaining threads);
//             see NOTE in gmw_circuit_by_gate.h about why we don't try to further
//             parallelize and subdivide a task between multiple threads.
//           > 3 threads.
//             Only 3 are used. see NOTE in gmw_circuit_by_gate.h about why we don't
//             try to further parallelize and subdivide a task between multiple threads.
//         See also discussion in (5) below regarding concurrency.
//
//      C) Extra Container for Values (see A.iii above).
//         To handle the corner case that we know a value (either from global input,
//         or as an output wire of an already evaluated gate) that is needed by
//         a gate whose index is too high, we do the following:
//             i) A global parameter 'max_gates_in_queue_' caps the size of 'Gates' queue
//            ii) A global parameter 'current_gate_index_' records the index of the
//                gate at the head of the 'Gates' queue
//           iii) A global (or class memeber variable) data structure of type
//                map<uint64_t, GenericValue> called '[left | right]_values_overflow_'
//                will store known values (keyed by the gate index the value maps to).
//                This data structure will be populated when 'Gates' has reached its
//                'max_gates_in_queue_' threshold, and the index of the last gate in
//                that queue (which has index value: current_gate_index_ +
//                max_gates_in_queue_) is not high enough to contain the gate index
//                that this value maps to. This data structure will be searched
//                (actually, since gates are processed in order and the
//                [left | right]_values_overflow_ maps remove an element when it
//                is used, the relevant value will be the first element in the map
//                if present) when the gate at the head of the Gates queue is
//                missing a value on its input wire.
//
//      D) Storing global output values.
//         There is a separate data structure for storing global outputs
//         (global_outputs_). However, we do not populate this
//         structure during circuit evaluation (as each output gate is
//         processed). Instead, global outputs are treated no differently
//         than all other (non-global) gate outputs: in the left_values_
//         queue (or in the left_overflow_values_ map, if necessary).
//         Then, after all gates have been evaluated, we'll go back through
//         left_[overflow_]values_ and extract out the global outputs.
//         NOTE: The reason we don't just populate global_outputs_
//         directly is due to how a gate is able to mark its outputs (wires):
//         via InputWireLocation, which has two fields for is_left (bool) and
//         index_ (GateIndexDataType). Since the data-type of the index is
//         strictly non-negative, we cannot e.g. indicate a global output by
//         overloading a negative sign. Instead, we make global outputs by
//         giving them index (num_gates_ + GLOBAL_OUTPUT_INDEX). Then, we
//         could identify these as we evaluate gates by checking each output
//         wire as we encounter them to see if the output index is >= num_gates_;
//         however, this would require an extra check for every output wire, and
//         it is more efficient (since the number of global outputs will be small
//         compared to the number of gates) just to handle these at the end.
//
//   2) Regarding Ordering (Indexing) of Global Inputs and Gates:
//      a) (Obviously) Gates should appear in the order they are to be evaluated,
//         i.e. gateX should have both inputs available when evaulation gets to it.
//      b) For optimal performance, parties' inputs will be read/processed
//         in-parallel to gate evaluation, as opposed to reading all inputs
//         and then proceeding to gate evaluation. This way, machines with many
//         processors can start evaluating gates as soon the first couple of
//         inputs have been read (so that reading in the rest of the inputs
//         can happen in-parallel as the gates are being evaluated).
//         This means that we'll need to order both the global inputs as well as
//         the gates in a manner that maximizes the number of gates that can be
//         evaluated as early as possible (i.e. with as few global inputs required).
//         The following considerations should be used to determine indexing of
//         global inputs:
//           (I.1) How many gates they (directly and indirectly) map to
//           (I.2) The *gate* indices they (directly and indirectly) map to
//         The following considerations should be used to determine indexing of gates:
//           (G.1) How many gates (directly and indirectly) depend on this gate
//           (G.2) The (gate/global input) indices of its input wire(s)
//         Note that (I.2) and (G.2) are naturally circular, so that a truly
//         optimized indexing will require a recursive search to find the
//         optimal ordering of Global Input/Gate indexing.
//
//  3) Regarding Circuit File Format:
//     Circuit files have the following eight components (a) - (h):
//       a) Function Fingerprint: Same as old circuit file format, e.g.:
//            f(x1, ..., xN; y1, ..., yM; ...; z1, ..., zL) = ...
//       b) Circuit size (total number of gates)
//       c) Number of OT bits required for each (P_i, P_j) pair.
//          NOTE: This corresponds to how many non-local gates depend on inputs
//          from *both* parties P_i and P_j.
//       d) Number of (global) outputs
//       e) A list of gates whose type is Arithmetic and that have (at least)
//          one input wire coming from a Bool gate (or BOOL global input).
//       f) (Global) input mappings for each party.
//          NOTE: The number of parties with input specifications should match
//          the number of parties on the LHS of the function fingerprint, and
//          the order that each Party's inputs appear should match the order
//          they appear in the fingerprint.
//       g) (Global) Constant inputs
//       h) Gate Info.
//     The first seven components (a) - (g) are collectively referred to as
//     the 'Metadata' block. These components have the following format:
//       (a) This has same format as in standard_circuit (indeed, we use
//           StandardCircuit.ParseFunctionString() to parse it).
//       (b) Format: "Num_Gates: X;", where X = Total number of gates (circuit size)
//       (c) For each pair of Parties (P_i, P_j), we present the number of
//           [Boolean | Arithmetic] (non-locally-computable) gates that
//           depend on inputs from both parties. There will be two lines (one for
//           Boolean, one for Arithmetic) that have a comma-separated list of exactly
//           (N-1)_C_2 = N(N-1)/2 values (the first N-1 values are how many (non-local)
//           gates that require inputs from P_0 and P_i (for i = 1..N-1); the next
//           N-2 values for for P_1 and P_i (for i = 2..N-1), and so forth.
//       (d) Format: "Num_Outputs: X;", where X = Total number of (global) outputs
//       (e) The list is a comma-separated list of elements of format:
//             INDEX:DTYPE
//           where DTYPE is numeric (enum) of the DataType. This list will be used to
//           populate datatypes_of_arith_from_bool_gates_ and should have info for every
//           Arithmetic gate (or global output that has non- Bool DataType) that has
//           input wires are BOOL.
//       (f) Format: "Party_Inputs (i):..." where i is the Party index, and what follows
//           (the ...) is a block of lines of format:
//             (DTYPE) [L|R]i0, [L|R]i1, ... [L|R]iL;
//             (DTYPE) [L|R]i0, [L|R]i1, ... [L|R]iL;
//             ...
//             (DTYPE) [L|R]i0, [L|R]i1, ... [L|R]iL;
//           Each line above represents a distinct input, and all the gates that
//           that input maps to. DTYPE is a keyword that represents the DataType of
//           that input (see CircuitByGate::ParseInputDataType() for mapping of
//           DataType <-> Keyword). Note that the line breaks and whitespace that appear
//           above don't actually exist; we instead use punctuation (',' and ';')
//           to demark boundaries between various targets and inputs, respectively.
//           Note: In case the DTYPE (Boolean vs. Arithmetic) of a global input does
//           not match the type of the Gate that it leads to, the list that specifies
//           where that input maps to should include not just the gate index, but
//           also a colon and a bit index:
//             [L|R]i:b, ...
//           Only the gates that have the opposite type need include bit specification,
//           thus a single global input can have some target gates listed in the simpler
//           '[L|R]i' notation and others in the more complex format '[L|R]i:b'.
//           The interpretation of the ':b' is as follows:
//             - If DTYPE is Bool, and target Gate is Arithmetic: Then the
//               'b' refers to which bit (of the target gate's input wire)
//               the global input maps to.
//             - If DTYPE is Non-Bool, and next Gate is Boolean: Then the
//               'b' refers to which bit of the current input
//               should be used when mapping to the target gate's input wire.
//       (g) This looks similar to (f), except with keyword/identifier "Constant Inputs:",
//           and with each term having format:
//             (DTYPE) VALUE [L|R]GATE_INDEX, [L|R]GATE_INDEX, ... [L|R]GATE_INDEX;
//           i.e. the 'VALUE' is extra for the CONSTANT_INPUTS block.
//       (h) Format: "Gate_Info:...", where what follows is a block of lines of format:
//             OP; DEPENDS_ON; OUTPUTS_TO_LEFT; OUTPUTS_TO_RIGHT; GLOBAL_OUTPUTS |
//             OP; DEPENDS_ON; OUTPUTS_TO_LEFT; OUTPUTS_TO_RIGHT; GLOBAL_OUTPUTS |
//             ...
//             OP; DEPENDS_ON; OUTPUTS_TO_LEFT; OUTPUTS_TO_RIGHT; GLOBAL_OUTPUTS |
//           where:
//             - The spaces shown above are not actually present
//             - OP: A numeric value in [0..(|CircuitOperation| - 1)].
//                   NOTE: We could've saved even more space by representing the
//                   gate op via a single character (by having a mapping from
//                   each value [0..255] that a char can be to a corresponding
//                   CircuitOperation), but since this would only save one
//                   character (byte) in the circuit file per gate, and since
//                   each gate anyway has at least 8 bytes anyway (for semi-
//                   colons, local, outputs, etc.), this 1-byte saving could
//                   *at best* reduce circuit file size by 12%, and more real-
//                   istically it would be negligible effect; so we don't bother.
//             - DEPENDS_ON: A list of all party (indices) that this gate depends on.
//                           More specifically, we specify all possible subsets of 2^N
//                           parties using an encoding of the binary string, where digit
//                           'i' (based on leftmost bit being labeled as digit '0')
//                           is '1' iff this gate depends on inputs from Party i.
//                           In particular, the DEPENDS_ON field will have *exactly*
//                           M = (\lceil N/8 \rceil) characters.
//             - OUTPUTS_TO_[LEFT | RIGHT]: Comma-separated list of gate indices
//               Note: In case the output type (Boolean vs. Arithmetic) of a child
//                     gate doesn't match the type of the gate itself, we'll need
//                     more info in the OUTPUTS_TO_[LEFT | RIGHT] list, namely,
//                     we adopt the ':b' suffix for such items in the OUTPUTS list,
//                     as described in the NOTE at the end of the (Global) Inputs
//                     comment (Metadata block (f)) above.
//             - GLOBAL_OUTPUTS: A comma-separated list of output indices.
//                               Ditto comment in  OUTPUTS_TO_[LEFT | RIGHT] above
//                               regarding handling of outputs that have different
//                               type than the gate itself.
//     NOTES:
//       a) Regarding DataType of global inputs: It will be assumed that global
//          inputs will have the type that matches the GateOp of the gate they
//          map to: If the GateOp is a BooleanOperation, the input type should
//          be bool (or GenericValue of type BOOL); if the GateOp is an
//          ArithmeticOperation, the input type should be GenericValue (of the
//          appropriate type). In case some input maps to multiple gates, which
//          themselves have different GateOp types (i.e. at least one is Boolean
//          and at least one is Arithmetic), the input should be viewed as two
//          (or more accurately, as 1 + (num bits in underlying DataType))
//          different inputs.
//       b) Regarding DataType of output (wires): There is some ambiguity/
//          complexity for when a gate has one type (Boolean vs. Arithmetic) and
//          (at least one of) its output wire(s) goes to a gate with the opposite
//          type. For such cases, we adopt the following convention:
//            Case: Gate is Boolean, Next Gate is Arithmetic:
//                    outputs_to_[left|right]_wire: i1:b, ..., iN:b
//                  where the index after the colon refers to which bit this
//                  value should populate.
//                  In case this gate has children of both (Bool and Arithmetic)
//                  types, the outputs_to_[left|right]_wire lines will be a list
//                  where some items (those that map to an Arithmetic gate) have
//                  colons ':' and others (those that map to another Bool gate) don't.
//            Case: Gate is Arithmetic, Next Gate is Boolean:
//                    outputs_to_[left|right]_wire: i1:b, ..., iN:b
//                  where the index after the column specifies which bit of the
//                  output value maps to that (Bool) gate index.
//                  In case this gate has children of both (Bool and Arithmetic)
//                  types, the outputs_to_[left|right]_wire lines will be a list
//                  where some items (those that map to an Arithmetic gate) have
//                  colons ':' and others (those that map to another Bool gate) don't.
//
//  4) Motivating how circuit information (gate operation type, circuit wiring,
//     and values (global inputs and from gate evaluation)) is stored.
//     The two main questions that arise are:
//       i) How to store values (of global inputs and outputs of evaluated gates)
//      ii) How (and when) to store gate info (gate op, input/output wirings, value)
//     Regarding (4.i) (Storage of Values), there are two main high-level design options:
//       1) Store each value once, and have all gates that need it point
//          back to the appropriate index within this 'Values' storage structure.
//       2) Store each value multiple times, at each gate that uses it.
//     In addition to the above choices, there is also the question of whether
//     values from global inputs should be treated different (i.e. stored
//     in a separate container) as values from evaluated gates.
//     In the case of (1), there is the additional consideration (which
//     will ultimately dictate the kind of data structure is best to use) of
//     whether a value is deleted from memory after it is no longer needed.
//     Indeed, given the fact that we want to support circuits with
//     many (> billions) of gates, we *must* delete values after they
//     are no longer needed. This then will prefer (2) over (1), since
//     there is not a data structure that is ideal for (1):
//       - Vector: Fast insert and lookup, but deletion slow. Also, keeping
//         track of where in the vector the appropriate value is stored
//         is complicated, since values are being deleted, and hence the
//         output value of gate N is not necessarily in vector-index 'N'.
//       - Map: Reasonable lookup, insert/delete, but not constant time
//       - Other?
//     Also, there are complicating issues with (1) in terms of how the
//     gates point back to the appropriate spot where the value is stored
//     (e.g. for a vector, we'd need the vector index, which may be hard
//     to compute and/or weird if we're also deleting things from the
//     vector). Also knowing when a value can be deleted would necessitate
//     storing the number of gates that need that value (and how many have
//     already used it). The complications are doable, but led us to choose (2).
//     Upon deciding to go with (2), there is yet a further consideration:
//     Should values be stored in the same data structure that contains
//     all the other gate information (gate op, wirings, etc.)? Or should
//     there be a separate 'Values' data structure, which is in 1-1
//     correspondence with the 'Gates' data structure? At first glance,
//     it may seem like there is no benefit of having a separate data
//     structure for the 'Values'. But, there are two reasons why this
//     might actually be preferred:
//       i) Concurrency. Based on the way we will handle concurrency
//          (see Discussion item (6) below), we demand each data structure
//          has at most one 'writing' thread and one 'reading' thread.
//          But, if we combine 'values' with the other 'gates' info,
//          then both the Circuit File Reader Thread and the Evaluate Gate
//          Thread and the Parse (Global) Inputs Thread will all need to write
//          to the 'gates' data structure
//      ii) No extra complexity. Since the size of the 'gates' data structure
//          will be bounded (to not exceed memory restrictions), we utilize
//          a separate data structure for some ('overflow') values anyway.
//          In particular, the 'gates' data structure was chosen to be a
//          Queue (to allow for quick deletion of already processed gates),
//          and for memory reasons, we cap the max size of this queue.
//          Then, what happens if we get a value (either from a global input
//          or from an evaluated gate's output) that maps to a gate that
//          cannot fit in 'gates'? For this reason, we created the
//          [left | right]_values_overflow_ map to store the extra values.
//     On the flip-side, there may be arguments for having a single container
//     combining the gate info (op, wiring) with the values, e.g.:
//       - Reduced memory overhead for a single structure vs. multiple containers;
//       - Reduced look-up time to look-up info in one structure vs. multiple
//         structures;
//       - Code complexity/bugginess: Have to ensure the Values and Gates
//         queues are in-sync.
//     The top two points above add minimal overhead, while the extra
//     code complexity of the third point is outweighed by the arguments in
//     (i) and (ii) above, so we opted to use separate containers for
//     storing gate info vs. values.
//
//     Finally, going back to implications of the choice of (1) over (2)
//     (see discussion near the top of (4)): This choice has implications
//     for the format of the circuit file: We now must know where output
//     wires go, since e.g. after evaluating a gate, we'll need to put the
//     value onto all gates it maps to. Thus, it makes more sense for the
//     circuit file to contain output (as opposed to input) wiring/mapping.
//     Note one subtle problem with this approach:
//     The 'Gate' object, which stores the gate operation, etc., may have
//     not yet been created (read from file) when we learn a value of one
//     of its inputs. This adds to code complexity (and also may strain memory)
//     of having to create the gate and store the value at it, before the
//     circuit file has parsed the gate yet.
//     Another subtle downside of designing things this way: because the
//     circuit file contains output (not input) wiring info, we now need to
//     explicitly have a section of the circuit file specify where all
//     global inputs map to (before, this info was implicit from wire
//     input info). The negative impact of this means that we'll need to
//     parse all inputs before we can start circuit evaluation; or at least,
//     we'll need to parse the (global) input section of the circuit file
//     before we can start gate evaluations (i.e. we can still optimize by
//     evaluating gates in parallel to reading (global) inputs: just have
//     gate evaluation hang if it doesn't have its inputs yet. This
//     re-emphasizes the importance of indexing (global) inputs complementary
//     to gate indexing, so that the first gates to be evaluated depend
//     on the first inputs to be processed.
//
//     Finally, regardless of choice of (1) vs. (2), there is still
//     a danger of running out of memory during circuit evaluation:
//     If there are lots of gates that have lots of outputs to gates
//     that are much lower in the circuit (and so the values don't
//     fit in the 'Values' data structure, but are stored in the
//     'overflow' values maps), then the overflow values map could
//     grow too large. At this point, it seems like this is an
//     unavoidable problem (i.e. there is *no* design that could
//     protect against such worst-case circuits), other than to e.g.
//     re-define the circuit (file) so that each gate has fewer outputs
//     (and in particular its output(s) go to 'nearby' gates), e.g.
//     enforcing 2-in-1-out circuit (namely the '1-out' part) so that
//     outputs are used/consumed as soon as possible.
//
//     Finally, in evaluating the trade-off of storing values from global
//     inputs together with values from evaluated gates: For concurrency,
//     it is easier to code/design these separately, to maintain our
//     'at most one 'push' thread per data structure' concurrency paradigm.
//     While this will have a small performance hit (we'll now need to pay
//     the cost to construct, look-up, and delete (total n*log(n) cost)
//     values into this map structure, as opposed to the linear (n) cost
//     of adding each global input value to the 'Values' queue), since
//     n (the number of global inputs) is likely to be small-ish, the extra
//     factor of log(n) is not likely to be a bottleneck (or even noticeable)
//     to overall running time of circuit evaluation, and thus the benefit
//     of simpler concurrency/code-complexity outweighs the cost.
//
//  5) Motivating the Format of the Circuit File; Discussion.
//     The logic for reading circuit files and evaluating a circuit should be
//     designed for optimal performance. This means choices were made to
//     optimize speed and memory, but with an eye towards supporting as many
//     circuits as possible. For example, using a vector to store intermediate
//     values (of evaluated gates) may be optimal in terms of speed, but only
//     if we don't need to delete values after they are no longer needed; and
//     then this in-turn constrains which circuits can be supported (circuits
//     with billions of gates may overflow memory). This in turn will affect
//     the format of the circuit file; as explained in the points below.
//     Also, there was a change in the circuit file representation between the
//     present 'Deep' (0.B above) file formats vs. the 'Flat' (0.A above) formats
//     regarding how circuit wiring is conveyed: for 0.A, the input wires of
//     each gate were specified, while for 0.B, we instead express output wiring.
//     This change also is due to our choice of how we store information/values
//     when doing the 'Deep' circuit evaluation. Namely, because we will store
//     a value at the gate it will be used (via the 'Values' or 'Values Overflow'
//     queue), we'll want to know as soon as we have a value (from gate evaluation
//     or global input) *where* that value should be placed/stored, and thus
//     relying on input wiring won't work, since we're not guaranteed to have
//     read all of the gates in the circuit yet, so we may not know all the
//     places the value is needed.
//
//  6) Concurrency.
//     The high-level design allows for multiple threads to be working
//     simultaneously, e.g. reading circuit file and gate evaluation
//     can happen in parallel (further concurrency partitioning of tasks
//     is done for GMW, where there are also threads for communicating
//     (pre-generated) OT bits and Send/Receive queues). But this will
//     mean that separate thread(s) will be reading/writing to the various
//     data structures (queues): for the present class, this is only the
//     gates_ queue (and the Values map for overflow); but for the n-Party
//     (GMW) extension, there are also queues for OT Bits and Send/Receive values.
//     C++ does not have any off-the-shelf concurrent data structures
//     (e.g. concurrent queues), so concurrency is handled as follows:
//       a) Each data structure will have one thread that
//          writes to it, and one thread that reads from it.
//       b) The well-defined/simple accessing property of (a) above means
//          that we don't require a full-fledged read/write concurrent
//          solution; which ultimately means a tailored solution can be
//          employed, resulting in faster execution. For example, we
//          don't need to have one thread block while the other is working.
//       c) The overall strategy will be as follows: Each queue will have
//          two threads that read/write from it: A 'write' thread, which
//          adds new values to the queue, and a 'read' thread, which reads
//          (and deletes) values from the queue. The underlying data
//          structure used for the queue is a ReadWriteQueue, which
//          under the hood is just a std::vector. Since std::vector is
//          threads safe, provided you don't have multiple threads
//          accessing the same position at the same time (and even this
//          is okay, provided both threads have 'const' access, i.e. they
//          are just 'reading'), and that you don't have one thread growing/
//          shrinking the vector while another is accessing it. Thus, we get
//          thread-safety for free, provided we follow the policy:
//              i) Queue (vector) size is set once-and-for-all at the outset,
//                 before the 'read' thread needs to access the Queue;
//             ii) The 'read' thread will always check that there is an
//                 element to 'read' before trying to read it
//            iii) The 'write' thread will make sure there is space in
//                 the Queue to 'push' the next element before pushing.
//          Properties (ii) and (iii) together will guarantee the 'read' and
//          'write' threads are never accessing the same element at the same time

#include "GenericUtils/init_utils.h"  // For GetNumCores().
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "StringUtils/string_utils.h"  // For Itoa().
#include "TestUtils/timer_utils.h"  // For Timer.
#include "circuit_utils.h"  // For OutputRecipient, etc.

#include <climits>  // For CHAR_BIT
#include <fstream>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <tuple>  // For std::tie, std::pair, std::tuple
#include <vector>

#ifndef STANDARD_CIRCUIT_BY_GATE_H
#define STANDARD_CIRCUIT_BY_GATE_H

namespace crypto {
namespace multiparty_computation {

// The maximum size of the Gates queue. This should be set as large as
// possible given system memory. Because the Gate object has size at
// least 16 bytes (8 bytes per output wire, 4 bytes per dependent party, and
// 4 bytes for gate op_), and there will be up to two copies of this; plus
// this code will have other memory reqiurements (Values map, and for
// GMW, Send/Receive and OT queues), so following seems reasonable safe-bound:
//   System Memory / kDefaultMaxGates >= 100 or 1000.
// Thus, the following default value will work if system has at least 1G memory.
static const GateIndexDataType kDefaultMaxGates =
    1024 * 1024;  // 2^20 ~= 1Million gates.
static const int64_t kDefaultReadFewBytes =
    1024 * 1024;  // 2^20 ~= 1Million gates.
static const unsigned char kBitIndexMask = 1 << (CHAR_BIT - 1);

// The value below is the default value for each of the
// xxx_thread_num_tasks_until_context_switch_ fields, which
// indicate when a thread should pause one task and start another.
// This value is only really used if the system only has one thread, and as
// such doing a context switch for a thread doesn't save overall time (since
// nothing can be parallelized), but there is still a potential memory issue.
// Thus, this value is set as high as possible (to minimize time wasted for
// context switching), but low enough so that system is not likely to run
// out of memory (will need to store gate info for this many gates). For example,
// if all gate info (gate op, input wire values, output value) can be encapsulated
// in X bytes, then we could roughly set this to:
//   System Memory / X
// plus we need some extra memory for temporary computation (e.g. gate evaluation,
// program memory, etc.). Estimating X ~= 512 bytes (3 GenericValues (8 bytes each
// for the two fields of GenericValue that have 4 bytes each, plus up to 128 bytes
// (the maximum size a GenericDataType, which is a string of 128 chars) for the
// two input wire values and the output wire value, plus some wiggle room),
// we'd want at most: SystemMemory/512.
// Setting instead X = 1kB and setting SystemMemory to at least 1Gb seem like
// reasonably safe estimates, hence the 1Gb/1kB = 1M threshold below.
// If system has 3 or more threads, this value isn't used. If system has 2 threads,
// it's also not really used.
static const uint64_t kDefaultNumGatesToProcessBeforeThreadSwitch = 1024 * 1024;

// Used for concurrency: Will indicate the status of a thread.
// NOTE: Could've probably squeezed all relevant info into a bool, but
// vector<bool> is poor design anyway, so need to at least use char, and then
// might as well use enum for code clarity, and can leverage the extra bits
// to convery more status options.
enum class ThreadStatus {
  UNKNOWN,
  UNSTARTED,
  ACTIVE,
  ASLEEP,
  PAUSED,  // E.g. for a context switch, for thread to do a different task.
  DONE,
  ABORTED,
  FAILED,
};
inline bool ThreadIsDone(const ThreadStatus status) {
  return (
      status == ThreadStatus::DONE || status == ThreadStatus::ABORTED ||
      status == ThreadStatus::FAILED);
}

// Used for concurrency: Will be used to match a task (e.g. ReadCircuitFile)
// to the thread (index, within thread_status_) that is handling that task.
enum class CircuitByGateTask {
  READ_CIRCUIT_FILE,
  PARSE_INPUTS,
  EVALUATE_CIRCUIT,
  // The following are used for multi-party (GMW) circuit evaluation.
  EXCHANGE_GLOBAL_INPUTS,
  GENERATE_OT_BITS,
  READ_OT_BITS,
  SEND_GATE_BITS,
  RECEIVE_GATE_BITS,
};

// In the case of multiple threads, when a thread is blocked and will go
// to sleep waiting for another thread to complete a task, this this
// enum keeps track of which use-case we're in, so that we can sanity-check
// that the thread it is waiting on is actually making progress (e.g. no
// race condition, and/or the other thread already failed and hence will
// never make progress).
enum class SleepReason {
  READ_GATE_INFO_FOR_EVAL,  // gates_ is full. Wait for Eval thread to clear space.
  PARSE_INPUTS_FOR_INPUT_INFO,  // Top block of circuit file not read yet.
  EVAL_FOR_INPUT_INFO,  // Top block of circuit file not read yet.
  EVAL_FOR_GATE_INFO,  // gates_ is empty. Wait for Read circuit thread to fill it.
  EVAL_FOR_INPUT_PARSING,  // Missing input wire info. Wait for Parse Global inputs.
  EVAL_FOR_OT_BITS,  // Relevant only for Gmw. OT bits for this gate not read yet.
};

// There are two pieces of info needed to convey the location of an input wire:
//   - The gate index
//   - Whether the input wire is the Left or Right input wire
struct InputWireLocation {
  bool is_left_;
  GateIndexDataType index_;

  InputWireLocation() {
    is_left_ = false;
    index_ = 0;
  }

  InputWireLocation(const bool is_left, const GateIndexDataType& index) {
    is_left_ = is_left;
    index_ = index;
  }

  // Overload < operator, so that InputWireLocation can be used as a key to a map/set.
  bool operator<(const InputWireLocation& x) const {
    return std::tie(index_, is_left_) < std::tie(x.index_, x.is_left_);
  }
  bool operator==(const InputWireLocation& x) const {
    return is_left_ == x.is_left_ && index_ == x.index_;
  }

  // Prints wire location in format: (is_left_, index).
  std::string Print() const {
    const std::string side = is_left_ ? "left" : "right";
    return "(" + side + ", " + string_utils::Itoa(index_) + ")";
  }
};

// There are three pieces of info we'll need to store in a Gate object to
// describe each of its output wires:
//   - Gate location (index and left vs. right wire), stored via 'InputWireLocation'
//   - Bit Index. Only used in the case that the child gate's op has opposite type
//     (Arith vs. Bool). For Arith -> Bool, this index says which bit of the output
//     value to use; for Bool -> Arith, it indicates which bit of the input gets
//     set by this gate's output (bit). Since all numeric DataTypes have at most
//     64 bits (and conversion from Bool <-> Arith is not relevant for non-numeric
//     DataTypes), the bit index will always be in [0..63], and thus can be stored
//     in a char field.
struct OutputWireLocation {
  InputWireLocation loc_;
  // If leading (most-significant) bit is zero, this field is ignored (i.e.
  // child gate has same type as parent gate, so no need for bit-index
  // specification). If leading bit is '1', the lower 7 bits give bit-index.
  unsigned char bit_index_;

  OutputWireLocation() { bit_index_ = 0; }

  explicit OutputWireLocation(const InputWireLocation& loc) {
    loc_ = loc;
    bit_index_ = 0;
  }

  // Warning: Only use this constructor if you want to specify a bit index (including
  // a bit index of zero). Otherwise, use above constructor.
  OutputWireLocation(const InputWireLocation& loc, const unsigned char bit) {
    loc_ = loc;
    if (bit < kBitIndexMask) {
      bit_index_ = (unsigned char) (bit + kBitIndexMask);
    } else {
      bit_index_ = bit;
    }
  }

  // Overload < operator, so that OutputWireLocation can be used as a key to a map/set.
  bool operator<(const OutputWireLocation& x) const {
    return std::tie(bit_index_, loc_) < std::tie(x.bit_index_, x.loc_);
  }
  bool operator==(const OutputWireLocation& x) const {
    return loc_ == x.loc_ && bit_index_ == x.bit_index_;
  }

  // Prints wire location in format: (is_left_, index:bit_index).
  std::string Print() const {
    const std::string side = loc_.is_left_ ? "left" : "right";
    const std::string bit_index = bit_index_ >= kBitIndexMask ?
        ":" + string_utils::Itoa(bit_index_ - kBitIndexMask) :
        "";
    return "(" + side + ", " + string_utils::Itoa(loc_.index_) + bit_index + ")";
  }
};

// Container to hold the fields that describe a global input:
//   - DataType of the input
//   - Mappings: All the gates this input maps to.
// Note: There is no field to specify *whose* input this comes from:
// For single-party circuit evaluation, this is N/A, but even for
// multi-party (GMW), the index within inputs_ (combined with info from
// circuit file Metadata, which is then stored in function_var_names_)
// indicates which party's input this comes from.
struct GlobalInputInfo {
  math_utils::DataType type_;
  std::set<OutputWireLocation> to_;

  GlobalInputInfo(const math_utils::DataType type) { type_ = type; }
  GlobalInputInfo(
      const math_utils::DataType type, const std::set<OutputWireLocation>& to) {
    type_ = type;
    to_ = to;
  }
};

struct Gate {
  // Describes the gate operation. is_boolean_ determines which of the other two
  // fields (boolean_op_ vs. arithmetic_op_) should be used (the other is
  // ignored, and should have value UNKNOWN).
  // NOTES: There are things going on here that emphasize minimizing memory
  // over code simplicity/readibility:
  //   - I could have a single field of type 'OperationHolder'.
  //     I don't do this because this has memory allocated for other Operation
  //     types (Comparison and Math) that are not needed
  //   - Originally, I had a three fields: A boolean to indicate if type was
  //     Boolean or Arithmetic, and then a BooleanOperation and a ArithmeticOperation,
  //     only one of which was used. But this wastes 1 bit for the bool and
  //     sizeof(enum) bits for the unused operation. Instead, this motivated the
  //     creation of a new 'CircuitOperation' enum class.
  math_utils::CircuitOperation op_;

  // Which players' inputs are required for this gate. Specifically, view the char
  // vector (of length N/8) as a length-N binary string, where position 'i' (with
  // left-most bit labeled at bit '0') is a '1' iff this gate depends on Party i.
  // We allow depends_on_ to be empty to represent the special case that this gate
  // depends on *all* parties (this is to speed-up computation for this common case).
  std::vector<char> depends_on_;

  // Output wiring.
  std::vector<OutputWireLocation> output_wires_;

  Gate() { op_ = math_utils::CircuitOperation::UNKNOWN; }
};

// Forward-declare various objects that are needed for friend functions
// of the CircuitByGate structure (used for converting between circuit formats).
template<typename T>
class StandardCircuit;
namespace scratch {
class sri_circuit;
class spar_gate;
class durasift_circuit;
};  // namespace scratch

// Forward declare, so it can be made a friend, as well as a parameter to EvaluateCircuit.
class GmwByGate;

struct CircuitByGate {
  friend class GmwByGate;

public:
  CircuitByGate() :
      // Instead of setting a default upper-bound for size of the gates_ and
      // [left | right]_values_ queues here (which requires reserving space
      // for them now), instead this is done when we actually know how much
      // space to reserve for them (so that we don't allocate more space than
      // is needed).
      //gates_(kDefaultMaxGates), left_values_(kDefaultMaxGates), right_values_(kDefaultMaxGates),
      read_gates_sleep_(),
      read_inputs_sleep_(),
      evaluate_gates_sleep_() {
    // Default is to use all available threads.
    const int num_cores = GetNumCores();
    num_threads_ = num_cores > 0 ? num_cores : 1;
    SetNumTasksUntilContextSwitch(true);

    // The following member variables are set for real in ReadCircuitFile():
    // In the circuit file metadata.
    num_levels_ = 0;
    num_gates_ = 0;
    num_outputs_ = 0;

    // The following member variables are set for real in ReadCircuitFile():
    // After reading circuit file metadata (except for circuit_filename_, which
    // can either be set via alternate constructor (below) or via SetCircuitFilename);
    circuit_filename_ = "";
    done_circuit_file_ = false;
    num_circuit_file_bytes_ = -1;
    is_circuit_file_function_read_ = false;
    is_circuit_file_num_gates_read_ = false;
    is_circuit_file_inputs_read_ = false;
    last_circuit_file_block_break_byte_ = 0;
    circuit_reader_thread_sleep_ms_ = 1000;  // 1s
    circuit_reader_thread_current_byte_ = 0;
    done_global_inputs_file_ = false;
    num_global_inputs_parsed_ = 0;

    // The following member variables are tracked in EvaluateCircuit().
    num_gates_processed_ = 0;
    num_curr_level_gates_processed_ = 0;
    num_levels_processed_ = 0;
    max_gates_in_queue_ = kDefaultMaxGates;

    debug_ = false;
    max_gates_sleep_time_ = 0;
    read_metadata_for_do_all_sleep_time_ = 0;
    read_metadata_for_inputs_sleep_time_ = 0;
    read_metadata_for_eval_sleep_time_ = 0;
    read_inputs_for_eval_sleep_time_ = 0;
    read_gates_for_eval_sleep_time_ = 0;
    read_inputs_for_eval_sleep_time_ = 0;

    // The remaining member variables are populated either:
    //   - During ReadCircuitFile() metadata (party_[one | two]_inputs_) or gates (gates_);
    //   - During ParseGlobalInputs() ([left | right]_[constant_]input_[values_]);
    //   - During EvaluateCircuit() ([left | right]_[overflow_]values_, global_outputs_).
  }
  CircuitByGate(const std::string& circuit_file) : CircuitByGate() {
    circuit_filename_ = circuit_file;
  }

  void SetNumThreads(const int num_threads) { num_threads_ = num_threads; }

  void SetMaxGateInQueue(const GateIndexDataType& max_gates) {
    max_gates_in_queue_ = max_gates;
  }

  // The following set values on the xxx_thread_num_tasks_until_context_switch_
  // member variables.
  // The rules for how these get set should respect the number of threads:
  //   - If num_threads_ == 1, then all tasks happen sequentially, and so
  //     all the xxx_context_switch_ fields should be set to the same value
  //   - If num_threads_ == 2, then the Read Circuit File task is done separately,
  //     while the other tasks (Parse Global Inputs, Evaluate Gates) are done
  //     sequentially. Thus, field for the former can be anything (e.g. -1),
  //     while the latter two should match.
  //   - If num_threads_ >= 3, then each task is done independent of the others,
  //     and hence these values can be set independent of each other (e.g. each -1).

  void SetNumTasksUntilContextSwitch(
      const bool is_non_gmw,
      const int64_t& num_tasks,
      const int64_t& small_num_tasks) {
    if (is_non_gmw) {
      eval_gates_thread_num_tasks_until_context_switch_ = num_tasks;
      parse_inputs_thread_num_tasks_until_context_switch_ = num_tasks;
      read_gates_thread_num_tasks_until_context_switch_ =
          num_threads_ == 1 ? num_tasks : -1;
    } else {
      parse_inputs_thread_num_tasks_until_context_switch_ = -1;
      eval_gates_thread_num_tasks_until_context_switch_ = num_tasks;
      read_gates_thread_num_tasks_until_context_switch_ = small_num_tasks;
    }
  }
  void SetNumTasksUntilContextSwitch(const bool is_non_gmw) {
    SetNumTasksUntilContextSwitch(
        is_non_gmw,
        (num_threads_ <= 2 ? kDefaultNumGatesToProcessBeforeThreadSwitch : -1),
        kDefaultReadFewBytes);
  }

  void SetCircuitFilename(const std::string& filename);

  // The primary tasks:
  //   (i) Read Circuit File
  //   (ii) Parse Inputs
  //   (iii) Evaluate Circuit
  //   (iv) Print Outputs (to file).
  // These can either be done all at once via DoAll(), or they can be called separately.
  // In the former case, concurrency is handled automatically (optimizes parallelization
  // and sequence of processing circuit file, input file, and circuit evaluation).
  // In the latter case, concurrency is handled by the caller, with features:
  //   - If is_done is NULL, then Sleep() whenever not able to continue
  //     (which can happen when memory caps are hit, or if prequisite
  //     processing hasn't been done yet, etc.)
  //   - If is_done is non-null, then return whenever not able to continue
  //     (is_done will be false in this case).
  // Here, 'not able to continue' means:
  //   - Within ReadCircuitFile():
  //       a) Memory limit (of gates_) is reached; OR
  //       b) read_gates_thread_num_tasks_until_context_switch_ is reached
  //   - Within ParseGlobalInputs():
  //       a) Input DataTypes haven't yet been read (from circuit file metadata)
  //   - Within EvaluateCircuit():
  //       a) Circuit File metadata not read yet; OR
  //       b) Global inputs not read yet; OR
  //       c) No more gates ready to process; OR
  //       d) eval_gates_thread_num_tasks_until_context_switch_ is reached
  // Note that caller is responsible for overriding default values, i.e. if
  // passing NULL is_done, probably should use the SetNumTasksUntilContextSwitch
  // API to set each xxx_thread_num_tasks_until_context_switch_ to -1.
  bool DoAll(const std::string& inputs_file, const std::string& outputs_file) {
    return DoAll(
        inputs_file, std::vector<math_utils::GenericValue>(), outputs_file);
  }
  // Same as above, alternate API for specifying inputs.
  bool DoAll(
      const std::vector<math_utils::GenericValue>& inputs,
      const std::string& outputs_file) {
    return DoAll("", inputs, outputs_file);
  }
  // The following API is generic so that this can be called as
  // a subroutine of GMW's circuit evaluation.
  bool ReadCircuitFile(
      const bool parse_function_formula, GmwByGate* parent, bool* is_done);
  // API for ReadCircuitFile() that does not take parameters for GMW related inputs.
  bool ReadCircuitFile(const bool parse_function_formula, bool* is_done) {
    return ReadCircuitFile(parse_function_formula, nullptr, is_done);
  }
  // API for ReadCircuitFile() that does not take parameters for GMW related inputs.
  bool ReadCircuitFile(bool* is_done) {
    return ReadCircuitFile(false, nullptr, is_done);
  }
  // NOTE: Even though circuits can specify two Parties (since same circuit file
  // can be used in the MPC/GMW setting), this function takes in a single input
  // file. In particular, for circuit (files) that specifies inputs from two
  // parties: 'filename' should list all P1 inputs followed by all P2 inputs.
  bool ParseGlobalInputs(const std::string& filename, bool* is_done) {
    return ParseGlobalInputs(
        filename, std::vector<math_utils::GenericValue>(), is_done);
  }
  // Same as above, alternate API for specifying inputs.
  bool ParseGlobalInputs(
      const std::vector<math_utils::GenericValue>& inputs, bool* is_done) {
    return ParseGlobalInputs("", inputs, is_done);
  }
  // Evaluate Circuit.
  // The following API is generic so that this can be called as a subroutine of GMW's
  // circuit evaluation, i.e. 'parent' will point to the GmwByGate object that
  // calls the present EvaluateCircuit() function as a subroutine, and
  // 'eval_gate_fn_ptr' is a function pointer to the member function EvaluateGate()
  // (within the GmwByGate class). [Note that we use a pointer to this function,
  // as opposed to just doing e.g. "parent->EvaluateGate(..)", because the latter
  // would require always linking gmw_circuit_by_gate.o whenever an executable needs
  // standard_circuit_by_gate.o, and this is often extraneous].
  bool EvaluateCircuit(
      const bool by_gate,
      const bool should_send,
      const bool should_receive,
      GmwByGate* parent,
      bool (*eval_gate_fn_ptr)(
          GmwByGate*,
          const bool,
          const bool,
          const bool,
          const math_utils::CircuitOperation,
          const std::vector<char>&,
          const math_utils::GenericValue&,
          const math_utils::GenericValue&,
          bool*,
          math_utils::GenericValue*),
      bool (*eval_level_fn_ptr)(GmwByGate*, const bool, const bool, const bool),
      bool* is_done);
  // API for EvaluateCircuit() that does not take parameters for GMW related inputs.
  bool EvaluateCircuit(bool* is_done) {
    return EvaluateCircuit(
        true, false, false, nullptr, nullptr, nullptr, is_done);
  }
  bool PrintOutputs(const std::string& filename) const;
  const std::vector<math_utils::GenericValue>& GetOutputs() const {
    return global_outputs_;
  }

  void SetDebug(const bool set_debug) { debug_ = set_debug; }
  std::string PrintTimerInfo() const;

  bool WriteCircuitFile(const std::string& filename) const;

  static bool ParseInputDataType(
      const int64_t& current_block_size,
      const char* memblock,
      math_utils::DataType* type,
      uint64_t* current_byte_index);

  // For convert_utils.ConvertCircuit(), we'll want private access to CircuitByGate's
  // private data members. Declare friend functions for all conversion directions.
  friend bool ConvertCircuit(const CircuitByGate* input, CircuitByGate* output);
  friend bool ConvertCircuit(
      const StandardCircuit<bool>* input, CircuitByGate* output);
  friend bool ConvertCircuit(
      const CircuitByGate* input, StandardCircuit<bool>* output);
  friend bool ConvertCircuit(
      const StandardCircuit<math_utils::slice>* input, CircuitByGate* output);
  friend bool ConvertCircuit(
      const CircuitByGate* input, StandardCircuit<math_utils::slice>* output);
  friend bool ConvertCircuit(
      const scratch::sri_circuit* input, CircuitByGate* output);
  friend bool ConvertCircuit(
      const CircuitByGate* input, scratch::sri_circuit* output);
  friend bool ConvertCircuit(
      const scratch::spar_gate* input, CircuitByGate* output);
  friend bool ConvertCircuit(
      const CircuitByGate* input, scratch::spar_gate* output);
  friend bool ConvertCircuit(
      const scratch::durasift_circuit* input, CircuitByGate* output);
  friend bool ConvertCircuit(
      const CircuitByGate* input, scratch::durasift_circuit* output);

private:
  // ============================= Member Variables ============================
  // --------------------------- Concurrency Fields ----------------------------
  int num_threads_;
  // Size of this vector should equal the number of tasks, which equals the
  // number of entries in CircuitByGateTask (currently 3).
  // This field is used to communicate info between threads, to ensure if one
  // thread (task) is hanging/stuck/aborted, the others know not to wait for it.
  // As such, it is only really used if num_threads_ > 1, and only really
  // used in DoAll(), when all three tasks are being done.
  std::map<CircuitByGateTask, ThreadStatus> thread_status_;
  // For optimization and/or memory, there are scenarios where a single thread
  // should cycle between different tasks. See discussion at top of this file;
  // succinctly:
  //   - For 1 thread (Memory):
  //     Cycle between reading circuit file, inputs, and evaluating gates;
  //   - For 2 threads (Memory):
  //     Cycle between reading (global) inputs file and evaluating gates;
  //   - For 3 or more threads:
  //     No cycling, each thread is designated a single task
  // The fields below specify the number of items to process for each task
  // before cycling to the next task (a value '-1' indicates no cycling; i.e.
  // keep doing same task until done).
  // Additionally, for optimization (parallelization), these fields are also used
  // by GmwByGate as follows:
  //   - For 1,2 threads (Parallelization):
  //     Cycle between reading circuit file, OT bits, and evaluating gates
  //     (which includes sending/receiving OT bits and Obf. TT's);
  //   - For 3,4 threads (Parallelization):
  //     Cycle between reading gate info and OT bits
  //   - For 5 or more threads:
  //     No cycling, each thread is designated a single task
  int64_t eval_gates_thread_num_tasks_until_context_switch_;
  int64_t read_gates_thread_num_tasks_until_context_switch_;
  int64_t parse_inputs_thread_num_tasks_until_context_switch_;

  // -------------------------- Circuit Metadata Info --------------------------
  // Variable Names for each Party (from Function Description LHS).
  std::vector<std::vector<std::string>> function_var_names_;
  // Description of mathematical formula for each output.
  std::vector<math_utils::Formula> function_description_;
  // Designation of where the outputs go, and the DataType of each output.
  std::vector<std::pair<OutputRecipient, math_utils::DataType>>
      output_designations_;
  GateIndexDataType num_levels_;
  GateIndexDataType num_gates_;
  std::vector<GateIndexDataType> num_gates_per_level_;

  // The following will be used to determine how many OT bits each player needs
  // to generate (with each of its Partners).
  // NOTE: This is only needed for GMW circuit evaluation, but we include this
  // field as part of CircuitByGate since GMW uses it as its base structure
  // (via the circuit_ member variable).
  std::vector<GateIndexDataType> num_non_local_boolean_gates_per_party_pairs_;
  std::vector<GateIndexDataType> num_non_local_arithmetic_gates_per_party_pairs_;

  // NOTE: This counts the number of actual outputs, as opposed to e.g. the
  // number of (global) output wires (e.g. for DataTypes with more than 1 bit,
  // we may use a BOOLEAN circuit that has a separate output wire for each
  // bit of this DataType).
  GateIndexDataType num_outputs_;
  // Whenever a gate (or a global output) takes input wires that have BOOL
  // values on them such that the BOOL values should be combined to form
  // a single value, we'll need to know how to combine them; namely we need
  // the DataType of the gate (or global output) to know if the bool wires
  // should be added (e.g. for Unsigned DataType), if leading bit is sign
  // bit (for Signed DataType), etc. This structure keeps track of the
  // DataType for all such Arithmetic gates (or global outputs) that have
  // input wires coming from a bool gate.
  std::map<GateIndexDataType, math_utils::DataType>
      datatypes_of_arith_from_bool_gates_;

  // ------------------------ Read Circuit File fields -------------------------
  test_utils::ExponentialEachNFailuresSleepTimer read_gates_sleep_;
  // Circuit File filename.
  std::string circuit_filename_;
  // Indicates circuit file has been fully processed.
  bool done_circuit_file_;
  // Number of bytes in the circuit file.
  int64_t num_circuit_file_bytes_;
  // Flags for determining how much of circuit file has been read.
  bool is_circuit_file_function_read_;
  bool is_circuit_file_num_gates_read_;
  bool is_circuit_file_inputs_read_;
  // In case circuit file reading gets interrupted (due to thread context switch,
  // or having read kMaxReadFileBlockBytes without reaching the end of the file),
  // this marks the last clean break point, i.e. where the thread should start
  // reading again; note that this index is w.r.t. the current block of the
  // circuit file, as opposed to the absolute byte index w.r.t. the full circuit file.
  uint64_t last_circuit_file_block_break_byte_;
  // The amount of time the 'ReadCircuitFile' Thread should wait (sleep) before
  // continuing to process the circuit file (from where it left off).
  // NOTE: The read circuit file thread can be put to sleep when:
  //   i) There is only one thread, then read info for X gates, then switch to
  //      evaluating X gates, etc.
  //      (where X = [read | eval]_gates_thread_num_tasks_until_context_switch_).
  //  ii) There are multiple threads (and so there is no reason to have the
  //      thread reading the circuit file alternate between tasks), but the
  //      gates_ size limit (max_gates_in_queue_) has been reached.
  // This field is only relevant for the second (ii) case, as the first-case
  // isn't truly putting the thread to sleep (thread will automatically switch
  // back to reading the circuit file when it finishes (part of) its other task).
  uint64_t circuit_reader_thread_sleep_ms_;
  // Used for when thread reading the circuit file needs to pause (either due to
  // case (i) or (ii) in NOTE above circuit_reader_thread_sleep_ms_): instructs
  // where to start reading from.
  int64_t circuit_reader_thread_current_byte_;

  // ------------------------ Read Global Inputs fields -------------------------
  test_utils::ExponentialEachNFailuresSleepTimer read_inputs_sleep_;
  bool done_global_inputs_file_;
  uint64_t num_global_inputs_parsed_;

  // ----------------------------- Evaulation Stats ----------------------------
  test_utils::ExponentialEachNFailuresSleepTimer evaluate_gates_sleep_;
  GateIndexDataType num_gates_processed_;
  GateIndexDataType num_curr_level_gates_processed_;
  GateIndexDataType num_levels_processed_;

  // ----------------------------- Input/Output Fields -------------------------
  // Input Mappings: Input index to InputWireLocation(s).
  // Notes:
  //   - The index of a global input (i.e. its location within the inputs_
  //     vector) is based completely on the function fingerprint (LHS),
  //     e.g. if function LHS is:
  //       f(x1, x2; y1, y2, y3; z1) = ...
  //     Then x1 will be the first (zeroth) entry in inputs_, and z1 the last.
  //   - Implicit is the assumption that all inputs have the appropriate type
  //     (Arithmetic vs. Boolean) as the target gate they are mapping to.
  //     Thus, e.g. for Arithmetic values, we don't need an inner-vector
  //     that describes where each bit of the input maps (as was done in
  //     standard_circuit.h's input_[one | two]_as_generic_value_locations_).
  //   - These just contain the input mappings, which can be (is) determined
  //     by the circuit file; the actual input values will be read in
  //     separately in the Inputs file(s), and the [left | right]_input_values_
  //     fields below will hold these values (the inputs_ mappings will be
  //     used in conjunction with the Input values file to populate
  //     [left | right]_input_values_)
  //   - Global constants are read from the circuit file (as opposed to the
  //     Inputs file(s)), but rather than store them analogously to inputs_,
  //     they are read directly into [left | right]_constant_inputs_ (below).
  std::vector<GlobalInputInfo> inputs_;
  // We'll also need a backwards map for every Party's input wires, namely, that
  // maps backwards from the input wire -> (Party index, input index).
  // Actually, the maps are more complicated than this, due to the fact that
  // we need to account for corner-cases of input DataType not matching gate
  // type (Arith vs. Bool):
  //   - Case A: For Non-Bool Input -> Bool Gate:
  //       We need to update the relevant bit of the input
  //   - Case B: For Bool Input -> Arith Gate:
  //       There will be multiple inputs (presumably all from same party)
  //       that map to (and set a different bit of the input wire of) this gate
  // Case A will force the map Values to have an extra coordinate for bit Index:
  //   (Party Index, Input Index, Bit Index),
  // with Bit Index set to -1 to indicate the standard case; while Case B will
  // force the Value to be a set of such tuples (in the standard case, this
  // set will just have size 1).
  // (This map will be used only for GMW evaluation, and is necessary to allow
  // computation of a gate based only on the parties whose input(s) the gate's
  // input wire(s) depend on).
  std::map<GateIndexDataType, std::set<std::tuple<int, int, int>>>
      left_input_wire_to_party_index_;
  std::map<GateIndexDataType, std::set<std::tuple<int, int, int>>>
      right_input_wire_to_party_index_;

  // Will store the final (global) output values.
  // NOTE: In case a Boolean circuit (or at least final output gates), the
  // wires have already been combined to form the final output value; thus,
  // global_outputs_.size() will match num_outputs_.
  std::vector<math_utils::GenericValue> global_outputs_;

  // ----------------------------- Gates/Values Fields -------------------------
  // Caps the size of gates_ and values_ queues.
  GateIndexDataType max_gates_in_queue_;

  // Gates queue. Per concurrency design, there are actually two queues:
  // one for reading and one for writing.
  ReadWriteQueue<Gate> gates_;

  // Values queues. There are a total of six containers:
  //  1-2) Left/Right values from Global inputs.
  //       NOTE: The left vs. right means which input wire the value should be
  //       placed on, NOT which party (P1 vs. P2) the input comes from.
  //  3-4) Left/Right values from evaluating gates
  //  5-6) Left/Right values for the 'overflow'
  // NOTES:
  // a) The [left | right]_values_ queue should always be in-sync with the gates_ queue.
  // b) Notice that when storing values in the maps (1, 2, 5, 6), the map Key is
  //    just the gate index (as opposed to InputWireLocation or OutputWireLocation,
  //    which include the additional info of right vs. left wire and bit-index):
  //      - We are able to drop/ignore the is_left_ field by having two Values_
  //        data structures, one for left wires and one for right wires.
  //      - We are able to drop the bit_index_ field by precomputing the relevant
  //        info, and storing as appropriate. I.e. for Arith -> Bool, we select the
  //        proper bit of the output and store that value in xxx_values_; and for
  //        Bool -> Arith, we have each output wire set the appropriate bit in the
  //        2's Complement vector of [left | right]_bool_to_arith_values_.
  std::map<GateIndexDataType, math_utils::GenericValue> left_input_values_;
  std::map<GateIndexDataType, math_utils::GenericValue> right_input_values_;
  std::map<GateIndexDataType, math_utils::GenericValue> left_constant_input_;
  std::map<GateIndexDataType, math_utils::GenericValue> right_constant_input_;
  ReadWriteQueue<math_utils::GenericValue> left_values_;
  ReadWriteQueue<math_utils::GenericValue> right_values_;
  std::map<GateIndexDataType, math_utils::GenericValue> left_overflow_values_;
  std::map<GateIndexDataType, math_utils::GenericValue> right_overflow_values_;
  std::map<GateIndexDataType, std::vector<unsigned char>>
      left_bool_to_arith_values_;
  std::map<GateIndexDataType, std::vector<unsigned char>>
      right_bool_to_arith_values_;

  // --------------------------- Timers (for debugging) ------------------------
  bool debug_;
  test_utils::Timer parse_global_inputs_timer_;
  test_utils::Timer read_circuit_file_timer_;
  test_utils::Timer evaluate_gates_timer_;
  int64_t read_metadata_for_do_all_sleep_time_;
  int64_t read_metadata_for_inputs_sleep_time_;
  int64_t read_metadata_for_eval_sleep_time_;
  int64_t read_gates_for_eval_sleep_time_;
  int64_t read_inputs_for_eval_sleep_time_;
  int64_t max_gates_sleep_time_;

  // ================================= Functions ===============================
  // Wrapper for DoAll() supporting either API.
  bool DoAll(
      const std::string& inputs_file,
      const std::vector<math_utils::GenericValue>& inputs,
      const std::string& outputs_file);
  // Wrapper for ParseGlobalInputs() supporting either API.
  bool ParseGlobalInputs(
      const std::string& filename,
      const std::vector<math_utils::GenericValue>& inputs,
      bool* is_done);
  bool ParseGlobalInputsInternal(const std::string& filename, bool* is_done);
  bool ParseGlobalInputsInternal(
      const std::vector<math_utils::GenericValue>& inputs, bool* is_done);
  // Internal helper function to load a global input value to the relevant field
  // [left | right]_input_values_, as per each location in 'targets'.
  bool ParseGlobalInput(
      const std::set<OutputWireLocation>& targets,
      const math_utils::GenericValue& value);
  //   - Reading Circuit File functions.
  bool ParseNumberOfGates(
      const int64_t& current_block_size,
      const char* memblock,
      uint64_t* current_byte_index);
  bool ParseFunctionDescription(
      const bool parse_function_formula,
      const int64_t& current_block_size,
      const char* memblock,
      uint64_t* current_byte_index);
  bool ParseGates(
      const bool started_parsing_gates,
      const bool wait_when_gates_is_full,
      const int64_t& current_block_size,
      const char* memblock,
      GmwByGate* parent,
      uint64_t* current_byte_index);
  bool ParseConstantInput(
      const int64_t& current_block_size,
      const char* memblock,
      math_utils::GenericValue* value,
      uint64_t* current_byte_index);
  bool ParseInputs(
      const int64_t& current_block_size,
      const char* memblock,
      uint64_t* current_byte_index);
  bool ReadCircuitFile(
      const bool parse_function_formula,
      std::ifstream& file,
      const int64_t block_size,
      GmwByGate* parent,
      bool* is_done);
  bool EvaluateCircuitByGate(
      const bool should_send,
      const bool should_receive,
      GmwByGate* parent,
      bool (*eval_gate_fn_ptr)(
          GmwByGate*,
          const bool,
          const bool,
          const bool,
          const math_utils::CircuitOperation,
          const std::vector<char>&,
          const math_utils::GenericValue&,
          const math_utils::GenericValue&,
          bool*,
          math_utils::GenericValue*),
      bool* is_done);
  bool EvaluateCircuitByLevel(
      const bool should_send,
      const bool should_receive,
      GmwByGate* parent,
      bool (*eval_gate_fn_ptr)(
          GmwByGate*,
          const bool,
          const bool,
          const bool,
          const math_utils::CircuitOperation,
          const std::vector<char>&,
          const math_utils::GenericValue&,
          const math_utils::GenericValue&,
          bool*,
          math_utils::GenericValue*),
      bool (*eval_level_fn_ptr)(GmwByGate*, const bool, const bool, const bool),
      bool* is_done);

  // Copies 'value' to all output locations in 'output_wires'.
  bool StoreOutputValue(
      const bool is_boolean_value,
      const std::vector<OutputWireLocation>& output_wires,
      math_utils::GenericValue& output_value);

  // Finds the status of the thread handling the indicated 'task' by looking
  // up the status from thread_status_.
  ThreadStatus GetThreadStatus(const CircuitByGateTask task);
  // Similar to above, the 'set' version.
  void SetThreadStatus(const CircuitByGateTask task, const ThreadStatus status);

  // When a thread cannot continue because it needs info/action items to be done
  // by another thread, we sanity-check the other thread(s) is/are making progress.
  // This means:
  //   a) If calling thread is Circuit File Reading thread:
  //      This thread never hangs before reading the top part of the file
  //      (everything except the Gates block). So, can only hang while reading
  //      the Gates block, and then, only hangs if gates_ is full.
  //   b) If calling thread is (Global) Input Parsing thread:
  //      This thread will sleep if:
  //        i) Top of circuit file not read yet (i.e. is_circuit_file_inputs_read_ = false)
  //   c) If calling thread is Gate Evaluation thread:
  //      This thread can hang for a couple of reasons:
  //        i) Top of circuit file not read yet (i.e. is_circuit_file_inputs_read_ = false)
  //       ii) Not enough gates_ pushed yet (by Circuit File Reading thread)
  //      iii) Not enough inputs parsed yet (by Input Parsing thread)
  bool IsProgressBeingMade(
      const SleepReason reason,
      const ThreadStatus circuit_reading_status,
      const ThreadStatus parse_inputs_status,
      const ThreadStatus eval_gates_status,
      int* num_sleeps,
      int* num_sleeps_two);
  // Same as above, if only one 'num_sleeps' is required (other is set to null).
  bool IsProgressBeingMade(
      const SleepReason reason,
      const ThreadStatus circuit_reading_status,
      const ThreadStatus parse_inputs_status,
      const ThreadStatus eval_gates_status,
      int* num_sleeps);
};

// Returns true if bit 'party_index' of 'depends_on' (when viewed as a
// binary string, with index '0' being the left-most bit) is '1'.
extern bool GateDependsOn(
    const int party_index, const std::vector<char>& depends_on);
// Returns the lowest index among all dependent parties; in other words,
// returns the location of the first '1' (when 'depends_on' is viewed as
// a binary string, with the left-most bit being position '0').
// Returns -1 if depends_on is all '0's.
extern int GetLowestDependentPartyIndex(const std::vector<char>& depends_on);
// Same as above, for fetching the highest dependent party index.
// Returns -1 if depends on is empty or all 0's.
extern int GetHighestDependentPartyIndex(const std::vector<char>& depends_on);
// Returns the number of parties whose input the present gate depends on
// (which is the number of 1's, when viewing 'depends_on' as a binary string).
extern int NumDependentParties(const std::vector<char>& depends_on);

// Helper functions for reading .function and .circuit_by_gate files.
extern bool ReadCircuitByGateMetadata(
    const std::string& filename,
    std::vector<math_utils::Formula>* function,
    std::vector<std::vector<std::pair<std::string, math_utils::DataType>>>*
        input_var_types,
    std::vector<std::pair<OutputRecipient, math_utils::DataType>>* output_types);
// Read the appropriate parts of the circuit file.
// Things allowed to be null (if you don't care about populating them):
//   - datatypes_of_arith_from_bool_gates
//   - num_non_local_boolean_gates_per_party_pairs
//   - num_non_local_arithmetic_gates_per_party_pairs
//   - inputs
//   - gates
extern bool ReadCircuitFile(
    const std::string& filename,
    std::vector<std::vector<std::string>>* function_var_names,
    std::vector<math_utils::Formula>* function_description,
    std::vector<std::pair<OutputRecipient, math_utils::DataType>>*
        output_designations,
    GateIndexDataType* num_levels,
    GateIndexDataType* num_gates,
    GateIndexDataType* num_outputs,
    std::map<GateIndexDataType, math_utils::DataType>*
        datatypes_of_arith_from_bool_gates,
    std::vector<GateIndexDataType>* num_non_local_boolean_gates_per_party_pairs,
    std::vector<GateIndexDataType>* num_gates_per_level,
    std::vector<GateIndexDataType>*
        num_non_local_arithmetic_gates_per_party_pairs,
    std::vector<GlobalInputInfo>* inputs,
    ReadWriteQueue<Gate>* gates);

}  // namespace multiparty_computation
}  // namespace crypto

#endif
