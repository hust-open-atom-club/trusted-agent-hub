'use client';

import { AnimatePresence, MotionConfig, motion, type Variants } from 'framer-motion';
import type { ReactNode } from 'react';

export { AnimatePresence, motion };

export function MotionProvider({ children }: { children: ReactNode }) {
  return (
    <MotionConfig reducedMotion="user">
      {children}
    </MotionConfig>
  );
}

export const pageStagger: Variants = {
  hidden: { opacity: 1 },
  visible: {
    opacity: 1,
    transition: {
      delayChildren: 0.04,
      staggerChildren: 0.08,
    },
  },
};

export const listStagger: Variants = {
  hidden: { opacity: 1 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.045,
    },
  },
};

export const fadeUp: Variants = {
  hidden: {
    opacity: 0,
    y: 18,
    filter: 'blur(4px)',
  },
  visible: {
    opacity: 1,
    y: 0,
    filter: 'blur(0px)',
    transition: {
      duration: 0.42,
      ease: [0.16, 1, 0.3, 1],
    },
  },
};

export const softPanel: Variants = {
  hidden: {
    opacity: 0,
    y: 10,
    scale: 0.985,
  },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.34,
      ease: [0.16, 1, 0.3, 1],
    },
  },
  exit: {
    opacity: 0,
    y: 8,
    scale: 0.985,
    transition: {
      duration: 0.18,
      ease: [0.7, 0, 0.84, 0],
    },
  },
};

export const listItem: Variants = {
  hidden: {
    opacity: 0,
    y: 12,
  },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.32,
      ease: [0.16, 1, 0.3, 1],
    },
  },
  exit: {
    opacity: 0,
    y: -8,
    transition: {
      duration: 0.16,
      ease: [0.7, 0, 0.84, 0],
    },
  },
};
