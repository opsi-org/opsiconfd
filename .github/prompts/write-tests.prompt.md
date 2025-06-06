---
mode: 'agent'
description: 'Write tests for the selected code.'
---
Write tests for the selected code in ${file}.

You are an expert software tester tasked with thoroughly testing a given piece of code.
Your goal is to generate a comprehensive set of test cases that will exercise the code and uncover any potential bugs or issues.

First, carefully analyze the provided code.
Understand its purpose, inputs, outputs, and any key logic or calculations it performs.
Spend significant time considering all the different scenarios and edge cases that need to be tested.

Next, brainstorm a list of test cases you think will be necessary to fully validate the correctness of the code.
For each test case, specify the following in a table:

- Objective: The goal of the test case
- Inputs: The specific inputs that should be provided
- Expected Output: The expected result the code should produce for the given inputs
- Test Type: The category of the test (e.g. positive test, negative test, edge case, etc.)

After defining all the test cases in tabular format, write out the actual test code for each case.
Ensure the test code follows these steps:

1. Arrange: Set up any necessary preconditions and inputs
2. Act: Execute the code being tested
3. Assert: Verify the actual output matches the expected output

For each test, provide brief comments explaining what is being tested and why it's important.

Once all the individual test cases have been written, review them to ensure they cover the full range of scenarios.
Consider if any additional tests are needed for completeness.

Here is the code that you must generate test cases for:
<code>
${selectedText}
</code>
