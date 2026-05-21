octopus.c 
潜在的 Bug 风险
SPX_OFFSER_COUNTER：在 octopus_compute_auth_paths 的第 4 步中，你使用了 SPX_OFFSER_COUNTER。请核对这个偏移量是否与你在 wots.c 中使用的 WOTS+C 计数器偏移量一致，避免在 ADRS 结构中互相覆盖。
leaf_count 与 SPX_TFORS_K：在 octopus_compute 中使用了 SPX_TFORS_K 作为循环上限，而在 octopus_compute_auth_paths 中使用了 leaf_count。
核查点：在 TFORS 中，每一棵小树揭露的叶子数可能是不确定的（取决于消息摘要的映射结果）。确保 octopus_compute 能够处理变长的 indices 数组，而不是假设总是 k个。